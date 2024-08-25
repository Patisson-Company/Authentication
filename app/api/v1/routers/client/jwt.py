from typing import Optional

from api.deps import ServesUsers_ServiceJWT, ServiceJWT
from fastapi import APIRouter, status
from patisson_errors import ErrorCode
from patisson_errors.fastapi import ErrorSchema, error
from patisson_tokens import ClientRole
from patisson_tokens.jwt.schemas import ClientPayload
from patisson_tokens.jwt.types import TokenBearer
from tokens.jwt import (Seconds, check_token, create_client_token,
                        create_refresh_token, create_sub, tokens_up)

router = APIRouter()

@router.get('/create')
async def create(service_jwt: ServesUsers_ServiceJWT, client_id: str, user_role: str, 
                 expire_in: Optional[Seconds] = None):
    # log level: INFO
    try:
        role = ClientRole(user_role)
    except ValueError as e:
        raise error(
            status_code=status.HTTP_400_BAD_REQUEST,
            errors=[ErrorSchema(error=ErrorCode.JWT_INVALID, extra=str(e))])  # ErrorCode.InvalidParameters

    return {
            "access_token": create_client_token(
                role=role,
                client_id=client_id,
                expires_in=expire_in
                ),
            "refresh_token": create_refresh_token(
                sub=create_sub(TokenBearer.CLIENT, client_id)
                )
            }
    
    
@router.get('/verify')
async def verify(service_jwt: ServiceJWT, user_access_token: str):
    is_valid, body = check_token(token=user_access_token, schema=ClientPayload)
    if is_valid:
        # log level: DEBUG
        return body
    else: 
        # log level: INFO
        raise body
    
    
@router.get('/update')
async def update(service_jwt: ServesUsers_ServiceJWT, client_access_token: str, 
                 client_refresh_token: str, expire_in: Optional[Seconds] = None):
    is_valid, body = tokens_up(
        refresh_token=client_refresh_token, 
        access_token=client_access_token, 
        schema=ClientPayload,
        expires_in=expire_in
        )
    # log level: INFO
    if is_valid:
        return {
            "access_token": body[0],
            "refresh_token": body[1]
            }
    else:
        raise body