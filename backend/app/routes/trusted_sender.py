from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from app.database.session import get_db
from app.auth.dependencies import get_current_user
from app.models.user import User
from app.models.trusted_sender import TrustedSender
from app.schemas.trusted_sender import TrustedSenderCreate, TrustedSenderResponse

router = APIRouter(prefix="/trusted-senders", tags=["Trusted Senders"])


@router.get(
    "",
    response_model=list[TrustedSenderResponse],
    status_code=status.HTTP_200_OK,
    summary="Get all trusted senders for the logged-in user"
)
async def get_trusted_senders(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    return db.query(TrustedSender).filter(TrustedSender.user_id == current_user.id).all()


@router.post(
    "",
    response_model=TrustedSenderResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Add a new trusted email or domain"
)
async def add_trusted_sender(
    payload: TrustedSenderCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Normalize values (lower-case and strip)
    value_clean = payload.value.strip().lower()
    
    # Check if duplicate exists
    existing = db.query(TrustedSender).filter(
        TrustedSender.user_id == current_user.id,
        TrustedSender.type == payload.type,
        TrustedSender.value == value_clean
    ).first()
    
    if existing:
        return existing
        
    db_trusted = TrustedSender(
        user_id=current_user.id,
        type=payload.type,
        value=value_clean
    )
    
    db.add(db_trusted)
    try:
        db.commit()
        db.refresh(db_trusted)
    except IntegrityError:
        db.rollback()
        existing = db.query(TrustedSender).filter(
            TrustedSender.user_id == current_user.id,
            TrustedSender.type == payload.type,
            TrustedSender.value == value_clean
        ).first()
        if existing:
            return existing
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to save trusted sender."
        )
    
    from app.services.ai_service import AIService
    AIService.sync_trusted_sender_emails(db, current_user)
    return db_trusted


@router.delete(
    "/{id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a trusted sender record"
)
async def delete_trusted_sender(
    id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    record = db.query(TrustedSender).filter(
        TrustedSender.id == id,
        TrustedSender.user_id == current_user.id
    ).first()
    
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Trusted sender record not found."
        )
        
    db.delete(record)
    db.commit()
    
    from app.services.ai_service import AIService
    AIService.sync_trusted_sender_emails(db, current_user)
    return


@router.delete(
    "/by-value",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a trusted sender record by value"
)
async def delete_trusted_sender_by_value(
    value: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    value_clean = value.strip().lower()
    record = db.query(TrustedSender).filter(
        TrustedSender.user_id == current_user.id,
        TrustedSender.value == value_clean
    ).first()
    
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Trusted sender record not found."
        )
        
    db.delete(record)
    db.commit()
    
    from app.services.ai_service import AIService
    AIService.sync_trusted_sender_emails(db, current_user)
    return
