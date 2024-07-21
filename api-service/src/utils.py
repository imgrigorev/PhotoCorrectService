import io

from fastapi.security import OAuth2PasswordBearer
from typing import Annotated

from fastapi import Depends, HTTPException, status
from models import TokenData, UserInDB, User
from datetime import datetime, timedelta, timezone
from passlib.context import CryptContext

import jwt
from PIL import Image, ImageEnhance
from io import BytesIO

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

fake_users_db = {
    "test": {
        "username": "test",
        "full_name": "Test Testov",
        "email": "johndoe@example.com",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
        "disabled": False,
    }
}


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)


def authenticate_user(fake_db, username: str, password: str):
    user = get_user(fake_db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except jwt.exceptions.PyJWTError:
        raise credentials_exception
    user = get_user(fake_users_db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(
        current_user: Annotated[User, Depends(get_current_user)],
):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


def compress_image(file, quality: int):
    image = Image.open(file.file)
    if image.mode not in ['RGB', 'L']:
        image = image.convert('RGB')

    buffer = io.BytesIO()
    image.save(buffer, format="JPEG", quality=quality)
    buffer.seek(0)
    return buffer


def resize_image(image_data: bytes, width: int, height: int) -> bytes:
    with Image.open(BytesIO(image_data)) as img:
        if img.mode not in ['RGB', 'L']:
            img = img.convert('RGB')

        img = img.resize((width, height))
        output = BytesIO()
        img.save(output, format='JPEG')
        return output.getvalue()


def add_watermark(base_image_data: bytes, watermark_image_data: bytes, position: tuple, opacity: float) -> bytes:
    with Image.open(BytesIO(base_image_data)) as base_img:
        if base_img.mode not in ['RGB', 'L']:
            base_img = base_img.convert('RGB')

        with Image.open(BytesIO(watermark_image_data)) as watermark_img:
            watermark_img = watermark_img.convert("RGBA")
            if opacity < 1:
                alpha = watermark_img.split()[3]
                alpha = ImageEnhance.Brightness(alpha).enhance(opacity)
                watermark_img.putalpha(alpha)

            base_img.paste(watermark_img, position, watermark_img)
            output = BytesIO()
            base_img.save(output, format='JPEG')
            return output.getvalue()
