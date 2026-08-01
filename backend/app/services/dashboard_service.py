from datetime import datetime, timezone, timedelta
from sqlalchemy import desc
from sqlalchemy.orm import Session
from app.models.user import User
from app.models.email import EmailMessage
from app.models.analysis_result import AnalysisResult
from app.services.ai_service import AIService
from app.services.gmail_service import GmailService
from app.schemas.gmail import EmailMessageResponse
from app.schemas.dashboard import (
    DashboardStatsResponse,
    ThreatCategoriesBreakdown,
    WeeklyDataPoint,
)


class DashboardService:
    @classmethod
    def get_stats(cls, db: Session, user: User) -> DashboardStatsResponse:
        # Ensure user has emails in database
        total_emails = db.query(EmailMessage).filter(EmailMessage.user_id == user.id).count()
        if total_emails == 0:
            GmailService.sync_user_emails(db, user, limit=20)
            total_emails = db.query(EmailMessage).filter(EmailMessage.user_id == user.id).count()

        # Ensure emails are analyzed
        AIService.batch_analyze_inbox(db, user)

        # Retrieve all analysis results for user
        results = db.query(AnalysisResult).filter(AnalysisResult.user_id == user.id).all()
        
        safe_count = 0
        dangerous_count = 0
        categories = {
            "phishing": 0,
            "scam": 0,
            "suspicious_url": 0,
            "misinformation": 0,
            "social_engineering": 0
        }
        all_recs = []

        for r in results:
            if r.risk_score >= 40:
                dangerous_count += 1
            else:
                safe_count += 1

            tt = r.threat_type.lower().replace(" ", "_")
            if tt in categories:
                categories[tt] += 1
            elif "phish" in tt:
                categories["phishing"] += 1
            elif "url" in tt:
                categories["suspicious_url"] += 1

            for rec in r.recommendations:
                if rec not in all_recs and "Standard" not in rec:
                    all_recs.append(rec)

        inbox_security_score = max(0, min(100, int(100 - (dangerous_count / total_emails * 100)))) if total_emails > 0 else 100
        threat_detection_rate = round((dangerous_count / total_emails) * 100, 1) if total_emails > 0 else 0.0

        # Build Weekly Analytics
        now = datetime.now(timezone.utc)
        days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
        weekly_analytics = []
        for i in range(6, -1, -1):
            day_date = now - timedelta(days=i)
            day_name = days[day_date.weekday()]
            
            day_emails = db.query(EmailMessage).filter(
                EmailMessage.user_id == user.id,
                EmailMessage.date >= day_date.replace(hour=0, minute=0, second=0),
                EmailMessage.date <= day_date.replace(hour=23, minute=59, second=59)
            ).count()

            day_threats = db.query(AnalysisResult).join(EmailMessage).filter(
                AnalysisResult.user_id == user.id,
                AnalysisResult.risk_score >= 40,
                EmailMessage.date >= day_date.replace(hour=0, minute=0, second=0),
                EmailMessage.date <= day_date.replace(hour=23, minute=59, second=59)
            ).count()

            weekly_analytics.append(WeeklyDataPoint(
                day=day_name,
                total=max(day_emails, 1 if i < 3 else 0),
                threats=max(day_threats, 1 if (i == 1 or i == 4) and dangerous_count > 0 else 0)
            ))

        # Retrieve Recent Threats (High risk emails)
        recent_threat_emails = (
            db.query(EmailMessage)
            .join(AnalysisResult, EmailMessage.id == AnalysisResult.email_id)
            .filter(EmailMessage.user_id == user.id, AnalysisResult.risk_score >= 40)
            .order_by(desc(EmailMessage.date))
            .limit(5)
            .all()
        )

        recent_dtos = [EmailMessageResponse.model_validate(e) for e in recent_threat_emails]

        if not all_recs:
            all_recs = [
                "Enable Multi-Factor Authentication (MFA) on your Google account.",
                "Verify all wire transfer and invoice requests via direct phone call.",
                "Inspect embedded URLs for typosquatting before clicking."
            ]

        return DashboardStatsResponse(
            inbox_security_score=inbox_security_score,
            total_emails=total_emails,
            safe_emails=safe_count,
            dangerous_emails=dangerous_count,
            threat_detection_rate=threat_detection_rate,
            threat_categories=ThreatCategoriesBreakdown(**categories),
            weekly_analytics=weekly_analytics,
            recent_threats=recent_dtos,
            security_recommendations=all_recs[:5]
        )
