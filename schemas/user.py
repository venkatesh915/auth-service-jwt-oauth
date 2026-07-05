from pydantic import BaseModel,EmailStr
from typing import Optional

from datetime import datetime

class UserCreate(BaseModel):
    username :str
    email :EmailStr
    phone :Optional[str] = None
    password:Optional[str] = None
    

class VerifyOTP(BaseModel):
    email :EmailStr
    otp : str

class LoginRequest(BaseModel):
    username: str
    password : str

class RefreshToken(BaseModel):
    refresh_token : str

class TokenResponse(BaseModel):
    access_token :str
    refresh_token :str
    token_type :str

class UserOut(BaseModel):
    id : int
    username:str
    email:EmailStr
    phone: Optional[str] = None
    role:str
    is_verified: bool
    is_deleted: bool
    created_at :datetime

    class Config:
        from_attributes = True
        


class ResendOTP(BaseModel):
    email :EmailStr

class ForgotPassword(BaseModel):
    email : EmailStr
    
class ResetPassword(BaseModel):
    email: EmailStr
    otp : str
    new_password : str


class UpdateProfile(BaseModel):
    username: str
    phone: str

class UpdateRole(BaseModel):
    role: str


class ChangePassword(BaseModel):
    current_password :str
    new_password :str