from typing import Callable, Optional, Type

import jwt
from fastapi import APIRouter, Body, HTTPException, Request, status
from pydantic import UUID4, EmailStr

from fastapi_users import models
from fastapi_users.utils import JWT_ALGORITHM, generate_jwt
from fastapi_users.router.common import ErrorCode, run_handler
from fastapi_users.user import (
    VerifyUserProtocol,
    SeekUserProtocol,
    UserAlreadyVerified,
    UserNotExists,
)
VERIFY_USER_TOKEN_AUDIENCE = "fastapi-users:verify"

def get_verify_router(
    verify_user: VerifyUserProtocol,
    seek_user: SeekUserProtocol,
    user_model: Type[models.BaseUser],
    after_verification_request: Callable[[models.UD, str, Request], None],
    verification_token_secret: str,
    verification_token_lifetime_seconds: int = 3600,
    after_verification: Optional[Callable[[models.UD, Request], None]] = None,
):
    router = APIRouter()

    @router.post(
        "/request_verify_token", status_code=status.HTTP_202_ACCEPTED
    )
    async def token_gen(request: Request, email: EmailStr = Body(..., embed=True)):
        try:
            user = await seek_user(email)
        except UserNotExists:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ErrorCode.VERIFY_USER_NOT_EXISTS,
            )
        if user.is_verified:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ErrorCode.VERIFY_USER_ALREADY_VERIFIED,
            )
        elif user.is_active:
            token_data = {
                "user_id": str(user.id),
                "email": email,
                "aud": VERIFY_USER_TOKEN_AUDIENCE,
            }
            token = generate_jwt(
                token_data,
                verification_token_lifetime_seconds,
                verification_token_secret,
            )

            await run_handler(after_verification_request, user, token, request)
        
        return None


    @router.post(
        "/verify", response_model=user_model, status_code=status.HTTP_202_ACCEPTED
    )
    async def verify(request: Request, token: str = Body(...)):
        try:
            data = jwt.decode(
                token,
                verification_token_secret,
                audience=VERIFY_USER_TOKEN_AUDIENCE,
                algorithms=[JWT_ALGORITHM],
            )
        except jwt.exceptions.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ErrorCode.VERIFY_USER_TOKEN_EXPIRED,
            )
        except jwt.PyJWTError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ErrorCode.VERIFY_USER_BAD_TOKEN,
            )

        user_id = data.get("user_id")
        email = data.get("email")
        if user_id is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ErrorCode.VERIFY_USER_BAD_TOKEN,
            )
        try:
            user_check = await seek_user(email)
        except UserNotExists:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ErrorCode.VERIFY_USER_BAD_TOKEN,
            )
        if not (str(user_check.id)==user_id):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ErrorCode.VERIFY_USER_BAD_TOKEN,
            )
        try:
            user_uuid = UUID4(user_id)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ErrorCode.VERIFY_USER_BAD_TOKEN,
            )

        try:
            user = await verify_user(user_uuid)
        except UserNotExists:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ErrorCode.VERIFY_USER_BAD_TOKEN,
            )
        except UserAlreadyVerified:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ErrorCode.VERIFY_USER_ALREADY_VERIFIED,
            )
        if after_verification:
            await run_handler(after_verification, user, request)
        return user
    
    return router
