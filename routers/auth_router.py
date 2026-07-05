from fastapi import APIRouter, Request, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import or_
from datetime import datetime, timedelta

from database.database import get_db
from models.user import User
from middleware.limiter import limiter
from core.config import settings

from schemas.user import (
    UserCreate, VerifyOTP, LoginRequest, RefreshToken, TokenResponse,
    ResendOTP, ForgotPassword, ResetPassword, UpdateProfile, ChangePassword
)

from auth.auth import (
    hash_password, verify_password, generate_otp, show_otp,
    create_access_token, create_refresh_token, decode_token,
    get_current_user, check_deleted
)

router =  APIRouter()
@router.post('/register')
def register(
    user:UserCreate,request:Request,
    db:Session = Depends(get_db)
):
    existing = db.query(User).filter(
        or_(
            User.username == user.username,
            User.email == user.email,
            User.phone == user.phone
        )
    ).first()

    if existing:
        raise HTTPException(400,"user already exists")
    otp = generate_otp()
    expiry = datetime.utcnow() + timedelta(minutes= settings.OTP_EXPIRE_MINUTES)

    new_user = User(
        username = user.username,
        email = user.email,
        phone = user.phone,
        password = hash_password(user.password),
        role = "user",
        otp = otp,
        otp_expiry = expiry,
        is_verified = False
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    show_otp(new_user.email,otp)
    return {
        "message" : "Registered successfully. OTP sent" 
    }


@router.post('/verify-otp')
@limiter.limit("3/minute")
def verify(
    request : Request,
    data :VerifyOTP,
    db: Session = Depends(get_db)

):
    user = db.query(User).filter(User.email == data.email).first()

    if not user:
        raise HTTPException (404,"user not found")
    
    check_deleted(user)

    if user.is_verified:
        raise HTTPException(400,"Already verified")
    if user.otp != data.otp:
        raise HTTPException(404,"Invalid otp")
    if user.otp_expiry is None or datetime.utcnow() > user.otp_expiry:
        raise HTTPException(400,"OTP expired")
    user.is_verified = True
    user.otp = None
    user.otp_expiry = None
    db.commit()
    return {
        "message" : "otp verified successfully"
    }

@router.post('/resend-otp')
@limiter.limit("2/minute")
def resend_otp(
    request: Request,
    data : ResendOTP,
    db:Session = Depends(get_db)

):
    user = db.query(User).filter(User.email == data.email).first()
    if not user:
        raise HTTPException(404," User not found")
    check_deleted(user)
    if user.is_verified:
        raise HTTPException(400,"already verified")
    otp = generate_otp()
    user.otp = otp
    user.otp_expiry = datetime.utcnow() + timedelta(minutes=settings.OTP_EXPIRE_MINUTES)

    db.commit()
    show_otp(user.email,otp)
    return {
        "message" : "new otp sent"
    }

# forget password

@router.post('/forgot-password')
@limiter.limit('2/minute')
def forgot_password(
    request : Request,data : ForgotPassword,
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.email == data.email).first()
    if not user:
        raise HTTPException(404,'user not found')
    
    check_deleted(user)

    otp = generate_otp()
    print("OTP:",otp)
    user.otp = otp
    user.otp_expiry = datetime.utcnow() + timedelta(minutes=settings.OTP_EXPIRE_MINUTES)
    db.commit()
    return {
        "message" : "otp sent for password reset"
    }

# reset password
@router.post("/reset-password")
@limiter.limit("3/minute")
def reset_password(
    request : Request,
    data : ResetPassword,
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.email == data.email).first()

    if not user:
        raise HTTPException (404,"user not found")
    check_deleted(user)
    if user.otp != data.otp:
        raise HTTPException(400,"invalid otp")
    if user.otp_expiry is None or datetime.utcnow() > user.otp_expiry:
        raise HTTPException(400,"otp expired")
    user.password = hash_password(data.new_password)
    user.otp = None
    user.otp_expiry = None
    db.commit()
    return {"message": "Password updated successfully"}


# =========================
# CHANGE PASSWORD
# =========================
@router.post("/change-password")
@limiter.limit("2/minute")
def change_password(
    request: Request,
    data: ChangePassword,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    check_deleted(current_user)

    # Verify current password
    if not verify_password(data.current_password, current_user.password):
        raise HTTPException(
            status_code=400,
            detail="Current password is incorrect"
        )

    # Prevent using the same password
    if verify_password(data.new_password, current_user.password):
        raise HTTPException(
            status_code=400,
            detail="New password cannot be the same as the current password"
        )

    # Hash and update the password
    current_user.password = hash_password(data.new_password)

    # Optional: Clear any leftover OTP fields
    current_user.otp = None
    current_user.otp_expiry = None

    db.commit()
    db.refresh(current_user)

    return {
        "message": "Password changed successfully"
    }



















# =========================
# LOGIN
# =========================
@router.post("/login", response_model=TokenResponse)
@limiter.limit("5/minute")
def login(
    request: Request,
    data: LoginRequest,
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.username == data.username).first()

    if not user:
        raise HTTPException(401, "Invalid credentials")

    if user.is_deleted:
        raise HTTPException(403, "Account is deactivated")

    if not verify_password(data.password, user.password):
        raise HTTPException(401, "Invalid credentials")

    if not user.is_verified:
        raise HTTPException(403, "Verify OTP first")

    access_token = create_access_token({
        "sub": user.username,
        "role": user.role
    })

    refresh_token = create_refresh_token({
        "sub": user.username,
        "role": user.role
    })

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }


# =========================
# REFRESH TOKEN
# =========================
@router.post("/refresh")
@limiter.limit("10/minute")
def refresh(
    request: Request,
    data: RefreshToken
):
    payload = decode_token(data.refresh_token, "refresh")

    new_token = create_access_token({
        "sub": payload["sub"],
        "role": payload["role"]
    })

    return {
        "access_token": new_token,
        "token_type": "bearer"
    }


# =========================
# UPDATE PROFILE
# =========================
@router.put("/update-profile")
@limiter.limit("10/minute")
def update_profile(
    request: Request,
    data: UpdateProfile,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    check_deleted(current_user)

    existing = db.query(User).filter(
        User.username == data.username,
        User.id != current_user.id
    ).first()

    if existing:
        raise HTTPException(400, "Username already exists")

    current_user.username = data.username
    current_user.phone = data.phone

    db.commit()
    db.refresh(current_user)

    return {
        "message": "Profile updated",
        "user": {
            "id": current_user.id,
            "username": current_user.username,
            "email": current_user.email,
            "phone": current_user.phone,
            "role": current_user.role
        }
    }
    






