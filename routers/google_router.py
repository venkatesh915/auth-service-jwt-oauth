from fastapi import APIRouter, Request, Depends, HTTPException
from sqlalchemy.orm import Session
import os

from auth.oauth_client import oauth
from database.database import get_db
from models.user import User
from auth.auth import create_access_token, create_refresh_token

router = APIRouter()



# =========================
# GOOGLE LOGIN
# =========================
@router.get("/login/google")
async def google_login(request: Request):
    redirect_uri = str(request.url_for('google_callback'))
    return await oauth.google.authorize_redirect(request, redirect_uri)
# =========================
# GOOGLE CALLBACK
# =========================
@router.get("/auth/google/callback", name="google_callback")
async def google_callback(request: Request, db: Session = Depends(get_db)):
    print("REQUEST URL:", request.url)
    token = await oauth.google.authorize_access_token(request)
    
    user_info = token.get("userinfo")
    if not user_info:
        print("USERINFO not in token, attempting to fetch from endpoint...")
        user_info = await oauth.google.userinfo(token=token)

    if not user_info:
        raise HTTPException(status_code=400, detail="Could not fetch user info from Google")

    email = user_info.get("email")
    if not email:
        raise HTTPException(status_code=400, detail="Could not fetch email from Google")
        
    username = user_info.get("name")
    if not username:
        first_name = user_info.get("given_name", "")
        last_name = user_info.get("family_name", "")
        username = f"{first_name} {last_name}".strip()
    
    if not username:
        username = email.split("@")[0]

    sub = user_info.get("sub")

 
    user = db.query(User).filter(
        User.email == email,
        User.oauth_provider == "google"
    ).first()

    # =========================
    # CREATE USER IF NOT EXISTS
    # =========================
    if not user:
        user = User(
            username=username,
            email=email,
            phone=None,

            password=None,              
            role="user",
            is_verified=True,
            is_deleted=False,

            oauth_provider="google"     # IMPORTANT
        )

        db.add(user)
        db.commit()
        db.refresh(user)

    # =========================
    # JWT TOKENS
    # =========================
    access = create_access_token({
        "sub": user.username,
        "role": user.role
    })

    refresh = create_refresh_token({
        "sub": user.username,
        "role": user.role
    })

    return {
        "access_token": access,
        "refresh_token": refresh,
        "token_type": "bearer",
        "user": {
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "oauth_provider": user.oauth_provider
        }
    }
