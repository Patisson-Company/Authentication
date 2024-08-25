from api.deps import ServiceJWT, SessionDep
from db.base import get_session
from db.crud_service import service_auth
from fastapi import APIRouter, status
from patisson_errors import ErrorCode, ErrorSchema
from patisson_errors.fastapi import error
from patisson_tokens import ServiceRole
from patisson_tokens.jwt.schemas import ServicePayload
from patisson_tokens.jwt.types import TokenBearer
from tokens.jwt import (check_token, create_refresh_token,
                        create_service_token, create_sub, tokens_up)

router = APIRouter()

@router.get('/create')
async def create(session: SessionDep, login: str, password: str):
    async with get_session() as session:
        service = await service_auth(session, login, password)
    if not service:
        raise error(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            errors=[ErrorSchema(error=ErrorCode.JWT_INVALID)]  # ErrorCode.BAD_CREDENTIALS
        )
    return {
            "access_token": create_service_token(
                role=ServiceRole(service.role),
                service_id=str(service.id)
                ),
            "refresh_token": create_refresh_token(
                sub=create_sub(TokenBearer.SERVICE, str(service.id))
                )
            }
    
    
@router.get('/verify')
async def verify(service_jwt: ServiceJWT, verified_service_jwt: str):
    is_valid, body = check_token(token=verified_service_jwt, schema=ServicePayload)
    if is_valid:
        # log level: DEBUG
        return body
    else: 
        # log level: INFO
        raise body
    
    
@router.get('/update')
async def update(service_jwt: ServiceJWT, refresh_token: str):
    is_valid, body = tokens_up(
        refresh_token=refresh_token, 
        access_token=service_jwt, 
        schema=ServicePayload
        )
    # log level: INFO
    if is_valid:
        return {
            "access_token": body[0],
            "refresh_token": body[1]
            }
    else:
        raise body
    
    