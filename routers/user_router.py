from fastapi import APIRouter, Depends
from models.user import User
from auth.auth import get_current_user

from middleware.limiter import limiter



router = APIRouter()


@router.get("/profile")
def profile(current_user: User = Depends(get_current_user)):
    return current_user


@router.get("/user-dashboard")
def dashboard(current_user: User = Depends(get_current_user)):
    return {
        "message": "User dashboard",
        "user": current_user.username
    }