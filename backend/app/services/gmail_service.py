import base64
import re
from datetime import datetime, timezone, timedelta
from email.utils import parsedate_to_datetime
import requests
from fastapi import HTTPException, status
from sqlalchemy import or_, desc
from sqlalchemy.orm import Session
from app.models.user import User
from app.models.oauth_token import OAuthToken
from app.models.email import EmailMessage

GMAIL_MESSAGES_URL = "https://gmail.googleapis.com/gmail/v1/users/me/messages"
URL_REGEX = re.compile(r'https?://[a-zA-Z0-9.\-_\~:/?#\[\]@!$&\'()*+,;=%]+')


class GmailService:
    @staticmethod
    def _extract_links(text: str) -> list[str]:
        if not text:
            return []
        matches = URL_REGEX.findall(text)
        # Deduplicate while preserving order
        seen = set()
        unique_links = []
        for link in matches:
            clean_link = link.rstrip('.,);"')
            if clean_link not in seen:
                seen.add(clean_link)
                unique_links.append(clean_link)
        return unique_links

    @staticmethod
    def _decode_body_data(data: str) -> str:
        if not data:
            return ""
        try:
            # Gmail uses URL-safe base64 encoding
            decoded_bytes = base64.urlsafe_b64decode(data.encode('ASCII'))
            return decoded_bytes.decode('utf-8', errors='replace')
        except Exception:
            return ""

    @classmethod
    def _parse_mime_parts(cls, payload: dict) -> tuple[str, str, list[dict]]:
        body_text = ""
        body_html = ""
        attachments = []

        def recurse_parts(parts_list):
            nonlocal body_text, body_html, attachments
            for part in parts_list:
                mime_type = part.get("mimeType", "")
                filename = part.get("filename", "")
                body = part.get("body", {})

                if filename:
                    attachments.append({
                        "filename": filename,
                        "mime_type": mime_type,
                        "size": body.get("size", 0)
                    })

                if mime_type == "text/plain" and not body_text:
                    body_text = cls._decode_body_data(body.get("data", ""))
                elif mime_type == "text/html" and not body_html:
                    body_html = cls._decode_body_data(body.get("data", ""))

                if "parts" in part:
                    recurse_parts(part["parts"])

        if "parts" in payload:
            recurse_parts(payload["parts"])
        else:
            mime_type = payload.get("mimeType", "")
            body_data = cls._decode_body_data(payload.get("body", {}).get("data", ""))
            if mime_type == "text/html":
                body_html = body_data
            else:
                body_text = body_data

        return body_text, body_html, attachments

    @classmethod
    def sync_user_emails(cls, db: Session, user: User, limit: int = 20) -> int:
        """
        Retrieves recent emails from Google Gmail API, parses headers, text/HTML body,
        links, attachments, upserts into database, and triggers AI threat analysis.
        """
        from app.services.auth_service import AuthService
        from app.services.ai_service import AIService
        from app.core.config import settings

        token_record = db.query(OAuthToken).filter(OAuthToken.user_id == user.id).first()

        # If user has a live token or can refresh
        if token_record and token_record.access_token and not token_record.access_token.startswith("demo_"):
            try:
                access_token = AuthService.get_valid_google_access_token(db, user.id)
                headers = {"Authorization": f"Bearer {access_token}"}
                params = {"maxResults": min(limit, 50)}
                res = requests.get(GMAIL_MESSAGES_URL, headers=headers, params=params, timeout=12)
                
                if res.status_code == 200:
                    messages_data = res.json().get("messages", [])
                    count = 0
                    new_email_ids = []
                    for msg_ref in messages_data[:limit]:
                        msg_id = msg_ref["id"]
                        
                        # Pre-check database to avoid redundant Google API detail calls
                        db_email = db.query(EmailMessage).filter(EmailMessage.id == msg_id).first()
                        if db_email:
                            continue

                        detail_url = f"{GMAIL_MESSAGES_URL}/{msg_id}?format=full"
                        msg_res = requests.get(detail_url, headers=headers, timeout=10)
                        if msg_res.status_code == 200:
                            raw_msg = msg_res.json()
                            payload = raw_msg.get("payload", {})
                            headers_list = payload.get("headers", [])
                            
                            header_map = {h["name"].lower(): h["value"] for h in headers_list}
                            sender = header_map.get("from", "Unknown Sender")
                            recipient = header_map.get("to", user.email)
                            subject = header_map.get("subject", "(No Subject)")
                            date_str = header_map.get("date")
                            
                            try:
                                msg_date = parsedate_to_datetime(date_str) if date_str else datetime.now(timezone.utc)
                            except Exception:
                                msg_date = datetime.now(timezone.utc)
 
                            body_text, body_html, attachments = cls._parse_mime_parts(payload)
                            full_text = f"{subject}\n{body_text}\n{body_html}"
                            extracted_links = cls._extract_links(full_text)
 
                            db_email = EmailMessage(
                                id=msg_id,
                                user_id=user.id,
                                thread_id=raw_msg.get("threadId"),
                                sender=sender,
                                recipient=recipient,
                                subject=subject,
                                date=msg_date,
                                snippet=raw_msg.get("snippet", body_text[:150]),
                                body_text=body_text,
                                body_html=body_html,
                                links=extracted_links,
                                attachments=attachments
                            )
                            db.add(db_email)
                            count += 1
                            new_email_ids.append(msg_id)

                    db.commit()

                    # Trigger automatic AI threat classification pipeline ONLY for newly synced emails
                    for new_id in new_email_ids:
                        try:
                            AIService.analyze_email_by_id(db, user, new_id)
                        except Exception as analysis_err:
                            print(f"Skipping sync-time analysis for email {new_id} due to warning: {analysis_err}")
                    return count
                else:
                    print(f"Gmail API response error ({res.status_code}): {res.text}")
            except Exception as e:
                print(f"Gmail API live sync issue: {e}")

        # Fallback Mock Seed Engine for Demo / Development Mode only
        if settings.ENABLE_DEV_DEMO:
            count = cls._seed_mock_emails(db, user, limit)
            AIService.batch_analyze_inbox(db, user)
            return count

        return 0


    @classmethod
    def _seed_mock_emails(cls, db: Session, user: User, limit: int = 20) -> int:
        """
        Seeds realistic security test emails with phishing URLs, invoice scams, and attachments.
        """
        mock_templates = [
            {
                "id": "msg_001_phishing_paypal",
                "sender": "service-security@paypaI-verify-login.com",
                "recipient": user.email,
                "subject": "URGENT: Your PayPal Account Has Been Suspended - Action Required",
                "date_offset_min": 10,
                "snippet": "We detected unauthorized login attempts from IP 192.168.1.1. Please verify your credentials immediately to avoid account closure.",
                "body_text": "Dear Customer,\n\nWe detected unauthorized login attempts on your account from an unrecognized device in Frankfurt, Germany.\n\nTo restore access, click the secure link below within 24 hours:\nhttp://paypaI-verify-login.com/login/auth-session-ref-98234\n\nFailure to do so will result in permanent suspension of your account funds.\n\nPayPal Security Team",
                "links": ["http://paypaI-verify-login.com/login/auth-session-ref-98234"],
                "attachments": []
            },
            {
                "id": "msg_002_scam_invoice",
                "sender": "billing-dept@accounts-finance-global.net",
                "recipient": user.email,
                "subject": "Invoice OVERDUE #INV-2026-9812 - Payment Required Immediately",
                "date_offset_min": 45,
                "snippet": "Attached is your overdue invoice for software consultancy services in the amount of $4,850.00 USD.",
                "body_text": "Attention Finance Department,\n\nPlease find attached the outstanding invoice #INV-2026-9812.\nAmount Due: $4,850.00 USD\n\nPlease transfer funds via wire transfer immediately to prevent legal collections.\n\nDownload Invoice Details: http://accounts-finance-global.net/pay/invoice9812.exe",
                "links": ["http://accounts-finance-global.net/pay/invoice9812.exe"],
                "attachments": [{"filename": "Invoice_9812.pdf.exe", "mime_type": "application/x-msdownload", "size": 245000}]
            },
            {
                "id": "msg_003_social_eng_ceo",
                "sender": "ceo.urgent.exec@gmail.com",
                "recipient": user.email,
                "subject": "Quick task - Are you at your desk right now?",
                "date_offset_min": 120,
                "snippet": "I am in a client meeting right now and need you to purchase 5 Apple Gift Cards for our project partners.",
                "body_text": "Hi,\n\nI'm tied up in an urgent executive meeting and cannot take calls. I need you to purchase 5x $100 Apple Gift cards right now for our client rewards presentation.\n\nSend the codes directly to this email as soon as possible. I will approve your expense report this afternoon.\n\nThanks,\nChief Executive Officer",
                "links": [],
                "attachments": []
            },
            {
                "id": "msg_004_misinformation_crypto",
                "sender": "news-alert@crypto-airdrop-claim-free.org",
                "recipient": user.email,
                "subject": "Government Approves $10,000 Stimulus AirDrop to All Email Users",
                "date_offset_min": 300,
                "snippet": "Breaking news: Federal reserve approves instant digital currency distribution. Connect wallet now.",
                "body_text": "Official Announcement:\n\nThe Department of Treasury has mandated an instant $10,000 digital stimulus payout to eligible email users.\n\nClaim your tokens here: https://crypto-airdrop-claim-free.org/connect-wallet\n\nLimited to the first 5,000 claims.",
                "links": ["https://crypto-airdrop-claim-free.org/connect-wallet"],
                "attachments": []
            },
            {
                "id": "msg_005_legit_google",
                "sender": "no-reply@accounts.google.com",
                "recipient": user.email,
                "subject": "Security Alert: New sign-in from Chrome on Windows",
                "date_offset_min": 450,
                "snippet": "Your Google Account was logged into from a new Windows device. If this was you, no action is needed.",
                "body_text": "Security Alert\n\nYour account demo.user@mailshield.ai was just signed in to on a Windows computer.\n\nIf this was you, you don't need to do anything.\nIf this wasn't you, review your account activity at https://myaccount.google.com/notifications",
                "links": ["https://myaccount.google.com/notifications"],
                "attachments": []
            }
        ]

        count = 0
        now = datetime.now(timezone.utc)
        for tpl in mock_templates[:limit]:
            existing = db.query(EmailMessage).filter(EmailMessage.id == tpl["id"]).first()
            msg_date = now - timedelta(minutes=tpl["date_offset_min"])
            if not existing:
                db_msg = EmailMessage(
                    id=tpl["id"],
                    user_id=user.id,
                    sender=tpl["sender"],
                    recipient=tpl["recipient"],
                    subject=tpl["subject"],
                    date=msg_date,
                    snippet=tpl["snippet"],
                    body_text=tpl["body_text"],
                    body_html=f"<div>{tpl['body_text'].replace('\n', '<br/>')}</div>",
                    links=tpl["links"],
                    attachments=tpl["attachments"]
                )
                db.add(db_msg)
                count += 1
        
        db.commit()
        return count

    @classmethod
    def get_paginated_emails(
        cls,
        db: Session,
        user: User,
        page: int = 1,
        size: int = 20,
        search: str | None = None
    ) -> tuple[list[EmailMessage], int]:
        """
        Retrieves stored emails for user with search filter and pagination.
        """
        query = db.query(EmailMessage).filter(EmailMessage.user_id == user.id)

        if search:
            search_pattern = f"%{search.strip()}%"
            query = query.filter(
                or_(
                    EmailMessage.subject.ilike(search_pattern),
                    EmailMessage.sender.ilike(search_pattern),
                    EmailMessage.recipient.ilike(search_pattern),
                    EmailMessage.body_text.ilike(search_pattern)
                )
            )

        total = query.count()
        offset = (page - 1) * size
        items = query.order_by(desc(EmailMessage.date)).offset(offset).limit(size).all()
        return items, total
