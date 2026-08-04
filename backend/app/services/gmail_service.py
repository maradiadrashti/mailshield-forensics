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

        # Check if we should override with a custom access token from environment (e.g. from env file)
        import os
        custom_token = os.getenv("MOCK_GOOGLE_ACCESS_TOKEN")
        if custom_token:
            token_rec = db.query(OAuthToken).filter(OAuthToken.user_id == user.id).first()
            if not token_rec:
                token_rec = OAuthToken(
                    user_id=user.id,
                    access_token=custom_token,
                    scope="https://www.googleapis.com/auth/gmail.readonly",
                    expires_at=datetime.now(timezone.utc) + timedelta(days=365)
                )
                db.add(token_rec)
            else:
                token_rec.access_token = custom_token
                token_rec.expires_at = datetime.now(timezone.utc) + timedelta(days=365)
            db.commit()

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

        return 0

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
