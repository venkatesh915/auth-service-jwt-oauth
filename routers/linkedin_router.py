from fastapi import APIRouter, Request, Depends, HTTPException
from sqlalchemy.orm import Session
import os

from auth.oauth_client import oauth
from database.database import get_db
from models.user import User
from auth.auth import create_access_token, create_refresh_token

router = APIRouter()



# =========================
# LINKEDIN LOGIN
# =========================
@router.get("/login/linkedin")
async def linkedin_login(request: Request):
    redirect_uri = str(request.url_for('linkedin_callback'))
    return await oauth.linkedin.authorize_redirect(request, redirect_uri)
# =========================
# LINKEDIN CALLBACK
# =========================
@router.get("/auth/linkedin/callback", name="linkedin_callback")
async def linkedin_callback(request: Request, db: Session = Depends(get_db)):
    try:
        print("REQUEST URL:", request.url)
        
        # --- WORKAROUND FOR LINKEDIN MISSING NONCE ---
        # LinkedIn's id_token often omits the nonce claim, causing authlib to crash.
        # We delete the nonce from the session before authlib checks it.
        state = request.query_params.get("state")
        if state:
            key = f"_state_linkedin_{state}"
            if key in request.session and "data" in request.session[key]:
                if "nonce" in request.session[key]["data"]:
                    del request.session[key]["data"]["nonce"]
        # ----------------------------------------------
        
        token = await oauth.linkedin.authorize_access_token(request)
        print("TOKEN:", token)
        
        user_info = token.get("userinfo")
        if not user_info:
            print("USERINFO not in token, attempting to fetch from endpoint...")
            user_info = await oauth.linkedin.userinfo(token=token)
            
        print("USER INFO:", user_info)
        
        if not user_info:
            raise HTTPException(status_code=400, detail="Could not fetch user info from LinkedIn")

        email = user_info.get("email")
        print("EMAIL:", email)
        if not email:
            raise HTTPException(status_code=400, detail="Could not fetch email from LinkedIn")
            
        username = user_info.get("name")
        if not username:
            first_name = user_info.get("given_name", "")
            last_name = user_info.get("family_name", "")
            username = f"{first_name} {last_name}".strip()
        
        if not username:
            username = email.split("@")[0]
            
        print("USERNAME:", username)

        sub = user_info.get("sub")

        # ✅ STRICT CHECK FOR LINKEDIN USERS ONLY
        user = db.query(User).filter(
            User.email == email,
            User.oauth_provider == "linkedin"
        ).first()
        print("EXISTING USER:", user)

        # =========================
        # CREATE USER IF NOT EXISTS
        # =========================
        if not user:
            # Check if email is already used by another provider
            existing_email_user = db.query(User).filter(User.email == email).first()
            if existing_email_user:
                print("WARNING: Email already in use by provider:", existing_email_user.oauth_provider)
                # You might want to link accounts, but for now we raise an error instead of a 500 DB crash
                raise HTTPException(status_code=400, detail=f"Email already registered with {existing_email_user.oauth_provider}")
                
            # Check if username is already used
            existing_username = db.query(User).filter(User.username == username).first()
            if existing_username:
                suffix = sub[:5] if sub else email.split("@")[0][:5]
                username = f"{username}_{suffix}"
                print("WARNING: Username already in use, changed to:", username)

            user = User(
                username=username,
                email=email,
                phone=None,

                password=None,              # ✅ IMPORTANT (no fake password for LinkedIn, requested NULL)

                role="user",
                is_verified=True,
                is_deleted=False,

                oauth_provider="linkedin"     # ✅ IMPORTANT
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
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise
