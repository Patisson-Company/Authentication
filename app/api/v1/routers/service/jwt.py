from api.deps import ServiceJWT, SessionDep
from db.base import get_session
from db.crud_service import service_auth
from fastapi import APIRouter, status
from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode
from patisson_errors import ErrorCode, ErrorSchema
from patisson_errors.fastapi import error
from patisson_tokens import ServiceRole
from patisson_tokens.jwt.schemas import ServicePayload
from patisson_tokens.jwt.types import TokenBearer
from tokens.jwt import (check_token, create_refresh_token,
                        create_service_token, create_sub, mask_token,
                        tokens_up)

router = APIRouter()
tracer = trace.get_tracer(__name__)

@router.get('/create')
async def create(session: SessionDep, login: str, password: str):
    
    with tracer.start_as_current_span("service-authentication") as span:
        span.set_attribute("service.login", login)
        span.set_attribute("service.password", mask_token(password, visible_chars=2))
        async with get_session() as session:
            service = await service_auth(session, login, password)
        span.add_event("the database request has been completed")
        span.set_attribute("db.query.service", service)
        
        if not service:
            span.set_status(Status(StatusCode.ERROR))
            raise error(
                status_code=status.HTTP_401_UNAUTHORIZED, 
                errors=[ErrorSchema(error=ErrorCode.BAD_CREDENTIALS)]
            )
    
    with tracer.start_as_current_span("creating-tokens") as span:
        access_token = create_service_token(
            role=ServiceRole(service.role),
            service_id=str(service.id)
            )
        span.add_event("access token is ready")
        span.set_attribute("service.created_access_token", mask_token(access_token))
        
        refresh_token = create_refresh_token(
            sub=create_sub(TokenBearer.SERVICE, str(service.id))
            )
        span.add_event("refresh token is ready")
        span.set_attribute("service.created_refresh_token", mask_token(refresh_token))
        
    return {
            "access_token": access_token,
            "refresh_token": refresh_token
            }
    
    
@router.get('/verify')
async def verify(service_jwt: ServiceJWT, verified_service_jwt: str):
    with tracer.start_as_current_span("verify") as span:
        span.set_attribute(f"service.verified_service_jwt", mask_token(verified_service_jwt))
        
        is_valid, body = check_token(token=verified_service_jwt, schema=ServicePayload)
        span.add_event("the token has been processed")
        span.set_attribute("service.is_verified_service_jwt_valid", is_valid)
        
        if is_valid:
            return body
        else: 
            span.set_status(Status(StatusCode.ERROR))
            raise body
        
    
@router.get('/update')
async def update(service_jwt: ServiceJWT, refresh_token: str):
    with tracer.start_as_current_span("tokens-up") as span:
        span.set_attribute("service.refresh_token", mask_token(refresh_token))
        
        is_valid, body = tokens_up(
            refresh_token=refresh_token, 
            access_token=service_jwt, 
            schema=ServicePayload
            )
        span.add_event("the tokens has been processed")
        span.set_attribute("service.is_tokens_valid", is_valid)
        
        if is_valid:
            span.set_attribute("service.created_access_token", mask_token(body[0]))
            span.set_attribute("service.created_refresh_token", mask_token(body[1]))
            return {
                "access_token": body[0],
                "refresh_token": body[1]
                }
        else:
            span.set_status(Status(StatusCode.ERROR))
            raise body
        
        