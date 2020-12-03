import jwt
from typing import Callable, Optional, Type
from fastapi_users.utils import JWT_ALGORITHM, generate_jwt
from fastapi import APIRouter, Body, HTTPException, Request, status
from fastapi_users import models
from pydantic import UUID4, EmailStr
from fastapi_users.router.common import ErrorCode, run_handler
from fastapi_users.user import (
    ActivateUserProtocol,
    SeekUserProtocol,
    UserAlreadyActivated,
    UserNotExists,
)
ACTIVATE_USER_TOKEN_AUDIENCE = "fastapi-users:activate"

def get_verify_router(
    activate_user: ActivateUserProtocol,
    seek_user: SeekUserProtocol,
    user_model: Type[models.BaseUser],
    activation_callback: Callable[[models.UD, str, Request], None],
    activation_token_secret: str,
    activation_token_lifetime_seconds: int = 3600,
    after_activation: Optional[Callable[[models.UD, Request], None]] = None,
):
    router = APIRouter()

    @router.post(
        "/request_verify_token", status_code=status.HTTP_202_ACCEPTED
    )
    async def token_gen(request: Request, email: EmailStr = Body(..., embed=True)):
        user = await seek_user(email)
        if user is not None and user.is_active:
            token_data = {
                "user_id": str(user.id),
                "email": email,
                "aud": ACTIVATE_USER_TOKEN_AUDIENCE,
            }
            token = generate_jwt(
                token_data,
                activation_token_lifetime_seconds,
                activation_token_secret,
            )
            await run_handler(activation_callback, user, token, request)
            return {"token": token}

    @router.post(
        "/activate", response_model=user_model, status_code=status.HTTP_202_ACCEPTED
    )
    async def activate(request: Request, token: str = Body(...)):
        try:
            data = jwt.decode(
                token,
                activation_token_secret,
                audience=ACTIVATE_USER_TOKEN_AUDIENCE,
                algorithms=[JWT_ALGORITHM],
            )
        except jwt.exceptions.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ErrorCode.ACTIVATE_USER_TOKEN_EXPIRED,
            )
        except jwt.PyJWTError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ErrorCode.ACTIVATE_USER_BAD_TOKEN,
            )

        user_id = data.get("user_id")
        email = data.get("email")
        if user_id is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ErrorCode.ACTIVATE_USER_BAD_TOKEN,
            )
        user_check = await seek_user(email)
        if not (str(user_check.id)==user_id):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ErrorCode.ACTIVATE_USER_BAD_TOKEN,
            )
        try:
            user_uuid = UUID4(user_id)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ErrorCode.ACTIVATE_USER_BAD_TOKEN,
            )

        try:
            user = await activate_user(user_uuid)
        except UserNotExists:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ErrorCode.ACTIVATE_USER_BAD_TOKEN,
            )
        except UserAlreadyActivated:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ErrorCode.ACTIVATE_USER_LINK_USED,
            )
        if after_activation:
            await run_handler(after_activation, user, request)
        return user
    
    return router
