from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """
    Base class for all SQLAlchemy ORM models in MailShield AI.
    Inherited by User, Email, AnalysisResult, and OAuthToken models.
    """
    pass
