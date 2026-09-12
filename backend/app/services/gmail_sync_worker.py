import asyncio
import logging
from app.database.session import SessionLocal
from app.models.user import User
from app.models.oauth_token import OAuthToken
from app.services.gmail_service import GmailService

logger = logging.getLogger("mailshield.services")


async def periodic_gmail_sync_loop(interval_seconds: int = 30):
    """
    Background worker that periodically polls the Gmail API for all active connected
    Google accounts, ingesting new emails and running the AI threat analysis pipeline.
    """
    logger.info(f"Starting periodic Gmail sync background worker (polling interval: {interval_seconds}s)")
    while True:
        try:
            await asyncio.sleep(interval_seconds)
            # Run database queries and sync in a separate thread to prevent blocking the async event loop
            await asyncio.to_thread(_sync_all_connected_users)
        except asyncio.CancelledError:
            logger.info("Periodic Gmail sync background worker cancelled gracefully.")
            break
        except Exception as e:
            logger.error(f"Unexpected error in periodic Gmail sync loop: {e}")


def _sync_all_connected_users():
    """
    Synchronizes emails for all users with active Google OAuth credentials.
    """
    db = SessionLocal()
    try:
        # Find all users with a non-demo OAuth token
        tokens = db.query(OAuthToken).filter(
            OAuthToken.refresh_token.isnot(None),
            ~OAuthToken.access_token.like("demo_%")
        ).all()

        if not tokens:
            return

        for token in tokens:
            user = db.query(User).filter(User.id == token.user_id).first()
            if not user:
                continue

            try:
                new_count = GmailService.sync_user_emails(db, user, limit=20)
                if new_count > 0:
                    logger.info(f"Background sync: Ingested {new_count} new email(s) for user {user.email}")
            except Exception as sync_err:
                logger.warning(f"Background sync notice for user {user.email}: {sync_err}")
    except Exception as db_err:
        logger.error(f"Database error during background sync: {db_err}")
    finally:
        db.close()
