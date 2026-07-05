from sqlalchemy import Column, String, Integer, DateTime, Boolean
from database.database import Base
from sqlalchemy.sql import func


class User(Base):
    __tablename__ = "users123"

    id = Column(Integer, primary_key=True, index=True)

    username = Column(String(100), unique=True, index=True, nullable=False)

    email = Column(String(50), unique=True, index=True, nullable=False)

    # ✅ FIXED: phone should be STRING + nullable
    phone = Column(String(15), nullable=True)

    password = Column(String(255), nullable=True)

    role = Column(String(20), nullable=True)

    otp = Column(String(6), nullable=True)
    otp_expiry = Column(DateTime, nullable=True)

    is_verified = Column(Boolean, default=False)
    is_deleted = Column(Boolean, default=False)

    created_at = Column(DateTime(timezone=True), server_default=func.now())

    oauth_provider = Column(String(50), nullable=True)