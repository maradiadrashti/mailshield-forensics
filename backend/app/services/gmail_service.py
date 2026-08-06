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
from app.core.config import settings, BASE_DIR

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
        import logging

        logger = logging.getLogger("mailshield.services")

        token_record = db.query(OAuthToken).filter(OAuthToken.user_id == user.id).first()

        if not token_record:
            logger.warning(f"No OAuthToken record found in database for user: {user.email}")
            return 0

        # Check if a custom gmail_token.txt exists in multiple possible locations
        import os
        import re
        from pathlib import Path
        
        possible_paths = [
            Path(BASE_DIR) / "gmail_token.txt",
            Path(BASE_DIR).parent / "gmail_token.txt"
        ]
        
        custom_token = None
        custom_refresh_token = None
        for path in possible_paths:
            if path.exists():
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        content = f.read()
                        # Extract access token (ya29. prefix)
                        access_match = re.search(r'(ya29\.[a-zA-Z0-9_\-\.\+]+)', content)
                        if access_match:
                            custom_token = access_match.group(1)
                        # Extract refresh token (1// prefix)
                        refresh_match = re.search(r'(1//[a-zA-Z0-9_\-\.\+]+)', content)
                        if refresh_match:
                            custom_refresh_token = refresh_match.group(1)
                    if custom_token:
                        logger.info(f"Loaded custom Google access token from: {path}")
                        break
                except Exception as read_err:
                    logger.error(f"Failed to read custom token file at {path}: {read_err}")

        if custom_token:
            logger.info("Found custom gmail_token.txt. Overriding stored access token and resetting expiry.")
            token_record.access_token = custom_token
            if custom_refresh_token:
                logger.info("Found custom refresh token in gmail_token.txt. Updating stored refresh token.")
                token_record.refresh_token = custom_refresh_token
            token_record.expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
            db.commit()

        used_custom_token = (custom_token is not None)

        # Determine if we are using the demo fallback token configuration
        is_demo = token_record.access_token and token_record.access_token.startswith("demo_")
        if is_demo:
            if settings.MOCK_GOOGLE_ACCESS_TOKEN:
                logger.info(f"Demo user with mock token configuration detected: {user.email}. Using MOCK_GOOGLE_ACCESS_TOKEN from environment for live sync.")
                access_token = settings.MOCK_GOOGLE_ACCESS_TOKEN
            else:
                logger.info(f"Demo user detected: {user.email}. Skipping live Gmail API sync.")
                return 0
        else:
            logger.info(f"Starting Gmail synchronization for user: {user.email} (limit: {limit})")

        try:
            # 1. Fetch access token (handles expiry check internally for real accounts)
            if not is_demo:
                access_token = AuthService.get_valid_google_access_token(db, user.id, force_refresh=False)
                
            headers = {"Authorization": f"Bearer {access_token}"}
            params = {"maxResults": min(limit, 50)}

            logger.info(f"Sending GET request to Gmail API messages list endpoint: {GMAIL_MESSAGES_URL}")
            res = requests.get(GMAIL_MESSAGES_URL, headers=headers, params=params, timeout=12)
            logger.info(f"Gmail API list response status: {res.status_code}")

            # 2. If token expired on Gmail side (receives 401), force refresh and retry
            if res.status_code == 401:
                if is_demo:
                    logger.error("MOCK_GOOGLE_ACCESS_TOKEN in .env is expired or invalid.")
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="The Google access token in your backend .env has expired. Please update MOCK_GOOGLE_ACCESS_TOKEN or sign in with Google."
                    )
                logger.warning(f"Received 401 Unauthorized from Gmail API. Attempting forced token refresh for user: {user.email}")
                try:
                    access_token = AuthService.get_valid_google_access_token(db, user.id, force_refresh=True)
                    headers = {"Authorization": f"Bearer {access_token}"}
                    
                    logger.info(f"Retrying GET request to Gmail API messages list endpoint: {GMAIL_MESSAGES_URL}")
                    res = requests.get(GMAIL_MESSAGES_URL, headers=headers, params=params, timeout=12)
                    logger.info(f"Gmail API list retry response status: {res.status_code}")
                except Exception as refresh_err:
                    if used_custom_token:
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail="google access token expired replace it to continue"
                        )
                    raise refresh_err

                if res.status_code == 401:
                    if used_custom_token:
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail="google access token expired replace it to continue"
                        )

            if res.status_code == 200:
                messages_data = res.json().get("messages", [])
                total_messages = len(messages_data)
                logger.info(f"Successfully retrieved list of {total_messages} messages from Gmail.")

                count = 0
                new_email_ids = []
                skipped_duplicates = 0

                for msg_ref in messages_data[:limit]:
                    msg_id = msg_ref["id"]
                    
                    # Pre-check database to avoid redundant Google API detail calls
                    db_email = db.query(EmailMessage).filter(EmailMessage.id == msg_id).first()
                    if db_email:
                        skipped_duplicates += 1
                        continue

                    detail_url = f"{GMAIL_MESSAGES_URL}/{msg_id}?format=full"
                    logger.info(f"Fetching details for Gmail message ID: {msg_id}")
                    msg_res = requests.get(detail_url, headers=headers, timeout=10)

                    if msg_res.status_code == 401:
                        if is_demo:
                            raise HTTPException(
                                status_code=status.HTTP_400_BAD_REQUEST,
                                detail="The Google access token in your backend .env has expired. Please update MOCK_GOOGLE_ACCESS_TOKEN or sign in with Google."
                            )
                        logger.warning(f"Received 401 Unauthorized during message detail fetch. Attempting token refresh.")
                        try:
                            access_token = AuthService.get_valid_google_access_token(db, user.id, force_refresh=True)
                            headers = {"Authorization": f"Bearer {access_token}"}
                            
                            logger.info(f"Retrying details fetch for Gmail message ID: {msg_id}")
                            msg_res = requests.get(detail_url, headers=headers, timeout=10)
                        except Exception as refresh_err:
                            if used_custom_token:
                                raise HTTPException(
                                    status_code=status.HTTP_400_BAD_REQUEST,
                                    detail="google access token expired replace it to continue"
                                )
                            raise refresh_err

                        if msg_res.status_code == 401:
                            if used_custom_token:
                                raise HTTPException(
                                    status_code=status.HTTP_400_BAD_REQUEST,
                                    detail="google access token expired replace it to continue"
                                )

                    logger.info(f"Gmail message detail response status for {msg_id}: {msg_res.status_code}")

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
                        logger.info(f"Successfully processed and staged email ID: {msg_id}")
                    else:
                        logger.error(f"Failed to fetch Gmail message details for ID: {msg_id}. Status: {msg_res.status_code}, Response: {msg_res.text}")
                        if msg_res.status_code == 401:
                            raise HTTPException(
                                status_code=status.HTTP_401_UNAUTHORIZED,
                                detail="Gmail API authentication failed during detail retrieval retry."
                            )

                if count > 0:
                    db.commit()
                    logger.info(f"Successfully committed {count} new email(s) to the database.")
                else:
                    logger.info("No new emails were found/processed. Database commit skipped.")

                logger.info(f"Sync stats - Fetched: {total_messages}, Limit: {limit}, Inserted: {count}, Skipped Duplicates: {skipped_duplicates}")

                # Trigger automatic AI threat classification pipeline ONLY for newly synced emails
                for new_id in new_email_ids:
                    try:
                        AIService.analyze_email_by_id(db, user, new_id)
                        logger.info(f"Successfully analyzed email {new_id} via threat classification pipeline.")
                    except Exception as analysis_err:
                        logger.warning(f"Skipping sync-time analysis for email {new_id} due to warning: {analysis_err}")
                return count
            else:
                logger.error(f"Gmail API list messages endpoint returned error status: {res.status_code}, Response: {res.text}")
                if res.status_code == 401:
                    if used_custom_token:
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail="google access token expired replace it to continue"
                        )
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Gmail API authentication failed. Please sign in again."
                    )
                else:
                    raise HTTPException(
                        status_code=status.HTTP_502_BAD_GATEWAY,
                        detail=f"Gmail API list messages request failed: Google returned HTTP {res.status_code}."
                    )
        except HTTPException as http_exc:
            logger.error(f"Authentication failure or HTTP exception in sync_user_emails: {http_exc.detail}")
            if used_custom_token and http_exc.status_code == 401:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="google access token expired replace it to continue"
                )
            raise http_exc
        except Exception as e:
            logger.exception(f"Unexpected exception during Gmail live sync: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Gmail API sync failed: {str(e)}"
            )

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
