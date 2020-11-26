from typing import Callable, Optional, Type, cast, Union
import jwt
from fastapi import APIRouter, HTTPException, Request, status
from pydantic import UUID4

from fastapi_users import models
from fastapi_users.db import BaseUserDatabase
from fastapi_users.password import get_password_hash
from fastapi_users.router.common import ErrorCode, run_handler
from fastapi_users.utils import JWT_ALGORITHM, generate_jwt
ACTIVATE_USER_TOKEN_AUDIENCE = "fastapi-users:activate"

def get_register_router(
    user_db: BaseUserDatabase[models.BaseUserDB],
    user_model: Type[models.BaseUser],
    user_create_model: Type[models.BaseUserCreate],
    user_db_model: Type[models.BaseUserDB],
    after_register: Optional[Callable[[models.UD, Request], None]] = None,
    activation_callback: Optional[Callable[[models.UD, str, Request], None]] = None,
    activation_token_secret: str = None,
    activation_token_lifetime_seconds: int = 3600,
) -> APIRouter:
    """Generate a router with the register route."""

    if activation_token_secret and not activation_callback:
        raise ValueError('Must supply activation_callback with activation_token_secret')
    elif activation_callback and not activation_token_secret:
        raise ValueError('Must supply activation_token_secret with activation_callback')
    
    router = APIRouter()
    @router.post(
        "/register", response_model=user_model, status_code=status.HTTP_201_CREATED
    )
    async def register(request: Request, user: user_create_model):  # type: ignore
        user = cast(models.BaseUserCreate, user)  # Prevent mypy complain
        existing_user = await user_db.get_by_email(user.email)

        if existing_user is not None and existing_user.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ErrorCode.REGISTER_USER_ALREADY_EXISTS,
            )

        hashed_password = get_password_hash(user.password)
        if existing_user is None:
            db_user = user_db_model(
                **user.create_update_dict(), hashed_password=hashed_password,
                is_active = not activation_callback
            )
            created_user = await user_db.create(db_user)
        else:
            created_user = existing_user

        if activation_callback:
            token_data = {"user_id": str(created_user.id), "aud": ACTIVATE_USER_TOKEN_AUDIENCE}
            token = generate_jwt(
                token_data,
                activation_token_lifetime_seconds,
                activation_token_secret,
            )
            await run_handler(activation_callback, created_user, token, request)
        elif after_register:
            await run_handler(after_register, created_user, request)
        
        return created_user

    if activation_callback:
        @router.get("/activate/{token}/", status_code=status.HTTP_202_ACCEPTED)
        @router.post("/activate/{token}/", status_code=status.HTTP_202_ACCEPTED)
        async def activate(request: Request, token: str):
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
            if user_id is None:
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

            user = await user_db.get(user_uuid)
            if user is None:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=ErrorCode.ACTIVATE_USER_BAD_TOKEN,
                )

            if user.is_active:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=ErrorCode.ACTIVATE_USER_LINK_USED,
                )
            user.is_active = True

            await user_db.update(user)
            if after_register:
                await run_handler(after_register, user, request)
    return router