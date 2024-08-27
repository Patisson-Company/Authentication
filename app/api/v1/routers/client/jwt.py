from typing import Optional

from api.deps import ServesUsers_ServiceJWT, ServiceJWT
from fastapi import APIRouter, status
from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode
from patisson_errors import ErrorCode
from patisson_errors.fastapi import ErrorSchema, error
from patisson_tokens import ClientRole
from patisson_tokens.jwt.schemas import ClientPayload
from patisson_tokens.jwt.types import TokenBearer
from tokens.jwt import (Seconds, check_token, create_client_token,
                        create_refresh_token, create_sub, tokens_up, mask_token)

router = APIRouter()
tracer = trace.get_tracer(__name__)

@router.get('/create')
async def create(service_jwt: ServesUsers_ServiceJWT, client_id: str, client_role: str, 
                 expire_in: Optional[Seconds] = None):
    with tracer.start_as_current_span("validate-parameters") as span:
        span.set_attribute("client.id", client_id)
        span.set_attribute("client.role", client_role)
        span.set_attribute("token.expire_in", expire_in)
        try:
            role = ClientRole(client_role)
        except ValueError as e:
            span.set_status(Status(StatusCode.ERROR))
            raise error(
                status_code=status.HTTP_400_BAD_REQUEST,
                errors=[ErrorSchema(error=ErrorCode.INVALID_PARAMETERS, extra=str(e))])
    
    with tracer.start_as_current_span("creating-tokens") as span:
        access_token = create_client_token(
            role=role,
            client_id=client_id,
            expires_in=expire_in
        )
        span.add_event("access token is ready")
        span.set_attribute("client.created_access_token", mask_token(access_token))
        
        refresh_token = create_refresh_token(
            sub=create_sub(TokenBearer.CLIENT, client_id)
        )
        span.add_event("refresh token is ready")
        span.set_attribute("service.created_refresh_token", mask_token(refresh_token))
        
    return {
        "access_token": access_token,
        "refresh_token": refresh_token
    }
    
    
@router.get('/verify')
async def verify(service_jwt: ServiceJWT, client_access_token: str):
    with tracer.start_as_current_span("verify") as span:
        span.set_attribute(f"client.passed_access_token", mask_token(client_access_token))
        
        is_valid, body = check_token(token=client_access_token, schema=ClientPayload)
        span.add_event(f"the token has been processed")
        span.set_attribute(f"client.is_access_token_valid", is_valid)
        
        if is_valid:
            return body
        else: 
            span.set_status(Status(StatusCode.ERROR))
            raise body
    
    
@router.get('/update')
async def update(service_jwt: ServesUsers_ServiceJWT, client_access_token: str, 
                 client_refresh_token: str, expire_in: Optional[Seconds] = None):
    with tracer.start_as_current_span("tokens-up") as span:
        span.set_attribute(f"client.passed_access_token", mask_token(client_access_token))
        span.set_attribute(f"client.passed_refresh_token", mask_token(client_refresh_token))
        span.set_attribute("token.expire_in", expire_in)
        
        is_valid, body = tokens_up(
            refresh_token=client_refresh_token, 
            access_token=client_access_token, 
            schema=ClientPayload,
            expires_in=expire_in
            )
        span.add_event("the tokens has been processed")
        span.set_attribute(f"client.is_tokens_valid", is_valid)
        
        if is_valid:
            span.set_attribute(f"client.created_access_token", mask_token(body[0]))
            span.set_attribute(f"client.created_refresh_token", mask_token(body[1]))
            return {
                "access_token": body[0],
                "refresh_token": body[1]
                }
        else:
            span.set_status(Status(StatusCode.ERROR))
            raise body