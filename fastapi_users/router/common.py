import asyncio
from typing import Callable


class ErrorCode:
    REGISTER_USER_ALREADY_EXISTS = "REGISTER_USER_ALREADY_EXISTS"
    LOGIN_BAD_CREDENTIALS = "LOGIN_BAD_CREDENTIALS"
    RESET_PASSWORD_BAD_TOKEN = "RESET_PASSWORD_BAD_TOKEN"
    ACTIVATE_USER_BAD_TOKEN = "ACTIVATE_USER_BAD_TOKEN"
    ACTIVATE_USER_LINK_USED = "ACTIVATE_USER_LINK_USED"
    ACTIVATE_USER_TOKEN_EXPIRED = "ACTIVATE_USER_TOKEN_EXPIRED"


async def run_handler(handler: Callable, *args, **kwargs):
    if asyncio.iscoroutinefunction(handler):
        await handler(*args, **kwargs)
    else:
        handler(*args, **kwargs)
