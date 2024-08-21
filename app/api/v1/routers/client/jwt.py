from typing import Optional

from dependencies.auth.jwt import validate_service_token
from fastapi import APIRouter, Depends
from patisson_tokens.jwt.schemas import ClientPayload, ServicePayload
from patisson_tokens.user_role import UserRole
from tokens.jwt import Seconds, check_token, create_client_token, tokens_up

router = APIRouter()

@router.get('/create')
async def create(user_role: str, expire_in: Optional[Seconds] = None, 
                 service_token_payload: ServicePayload = Depends(validate_service_token)):
    # log level: INFO
    return create_client_token(
        sub=service_token_payload.sub,
        role=UserRole(user_role),
        expires_in=expire_in
        )
    
@router.get('/verify')
async def verify(user_access_token: str,
                 service_token_payload: ServicePayload = Depends(validate_service_token)):
    is_valid, body = check_token(token=user_access_token, schema=ClientPayload)
    if is_valid:
        # log level: DEBUG
        return body
    else: 
        # log level: INFO
        raise body
    
@router.get('/update')
async def update(client_access_token: str, client_refresh_token: str,
                 service_token_payload: ServicePayload = Depends(validate_service_token)):
    is_valid, body = tokens_up(refresh_token=client_refresh_token, 
                     access_token=client_access_token, schema=ClientPayload)
    # log level: INFO
    if is_valid:
        return {
            "access_token": body[0],
            "refresh_token": body[1]
            }
    else:
        raise body
    
    