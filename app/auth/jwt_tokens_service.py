from datetime import datetime, timedelta, timezone
from app.models.token import Token
from app.models.user import User
from sqlmodel import Session
from app.config import settings
import jwt


def create_access_token(data: dict):
    expires_delta = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, "ba3cf318a0b11cf763c4fc0a853946ec40d43647dd2a52257fc2349c5bc57d70", algorithm=settings.ALGORITHM)
    return encoded_jwt

def verify_token(token: Token, session: Session):
    payload = jwt.decode(token, "ba3cf318a0b11cf763c4fc0a853946ec40d43647dd2a52257fc2349c5bc57d70", algorithms=[settings.ALGORITHM])
    username = payload.get("sub")
    return User.find_by_username(db=session, username=username)
    