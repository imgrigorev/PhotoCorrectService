from datetime import timedelta
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, status, UploadFile, File, Form
from fastapi.security import OAuth2PasswordRequestForm

from models import User, Token
from utils import (
    authenticate_user,
    create_access_token,
    get_current_active_user,
    fake_users_db,
    ACCESS_TOKEN_EXPIRE_MINUTES,
    resize_image,
    add_watermark,
    compress_image)
from fastapi.responses import StreamingResponse
import io

app = FastAPI()


@app.post("/token")
async def login_for_access_token(
        form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> Token:
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")


@app.get("/users/me/", response_model=User)
async def read_users_me(
        current_user: Annotated[User, Depends(get_current_active_user)],
):
    return current_user


@app.get("/users/me/items/")
async def read_own_items(
        current_user: Annotated[User, Depends(get_current_active_user)],
):
    return [{"item_id": "Foo", "owner": current_user.username}]


@app.post("/compress-image/")
async def compress_image_func(
        file: UploadFile = File(...),
        quality: int = 4
):
    return StreamingResponse(compress_image(file, quality=quality), media_type="image/jpeg")


@app.post("/resize-image/")
async def resize_image_func(
        file: UploadFile = File(...),
        width: int = 100,
        height: int = 100
):
    image_data = await file.read()
    resized_image_data = resize_image(image_data, width, height)
    return StreamingResponse(io.BytesIO(resized_image_data), media_type="image/jpeg")


@app.post("/add-watermark/")
async def add_watermark_func(
        base_image: UploadFile = File(...),
        watermark_image: UploadFile = File(...),
        position_x: int = Form(...),
        position_y: int = Form(...),
        opacity: float = Form(...),
):
    base_image_data = await base_image.read()
    watermark_image_data = await watermark_image.read()
    position = (position_x, position_y)
    watermarked_image_data = add_watermark(base_image_data, watermark_image_data, position, opacity)
    return StreamingResponse(io.BytesIO(watermarked_image_data), media_type="image/jpeg")
