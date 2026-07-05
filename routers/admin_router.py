from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from middleware.limiter import limiter
from schemas.user import UserOut, UpdateRole
from typing import List

from database.database import get_db
from models.user import User
from auth.auth import admin_required

router = APIRouter()


@router.get('/admin-dashboard')
def admin_dashboard(current_user : User = Depends(admin_required)):
    return {"message":"Admin dashboard"}

@router.get('/admin/users',response_model=List[UserOut])
def get_users(
    db:Session= Depends(get_db),
    current_user:User = Depends(admin_required)
):
    return db.query(User).all()

@router.delete('/admin/user/{user_id}')
def delete_user(
    user_id :int,
    db:Session = Depends(get_db),
    current_user :User =  Depends(admin_required)
):
    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        raise HTTPException(404,"User not found")
    
    if user.id ==current_user.id:
        raise HTTPException(400,"cannot delete yourself")
    db.delete(user)
    db.commit()
    return {
        'message' : 'User deleted'
    }

@router.delete('/user/soft-delete/{user_id}')
def soft_delete_user(
    user_id : int,
    current_user :User = Depends(admin_required),
    db: Session = Depends(get_db)
):
    user =  db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(404,"user not found")
    user.is_deleted = True
    db.commit()
    return {
        "message" : "user deactivated(soft delete)"
    }

@router.put('/admin/user/{user_id}/role')
def update_user_role (
    user_id :int,
    data : UpdateRole,
    db:Session=Depends(get_db),
    admin:User = Depends(admin_required)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(404,"user not found")
    if data.role not in ['admin','user']:
        raise HTTPException(400,"Role must be 'admin' or 'user'")
    user.role = data.role
    db.commit()
    db.refresh(user)

    return {
        "message" : "role updated sucessfully",
        "user" : {
            "id" : user.id,
            "username" : user.username,
            "role" : user.role
        }
    }