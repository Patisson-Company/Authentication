from typing import Optional

from api.deps import ServesUsers_ServiceJWT, ServiceJWT
from api.v1.routers.shemas import (CreateClientRequest, UpdateClientRequest,
                                   VerifyRequest)
from fastapi import APIRouter, HTTPException, status
from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode
from patisson_request.errors import ErrorCode, ErrorSchema
from patisson_request.jwt_tokens import ClientPayload, TokenBearer
from patisson_request.service_responses import AuthenticationResponse
from patisson_request.service_roles import ClientRole
from tokens.jwt import (check_token, create_client_token, create_refresh_token,
                        create_sub, mask_token, tokens_up)

router = APIRouter()
tracer = trace.get_tracer(__name__)

@router.post('/create')
async def create(service_jwt: ServesUsers_ServiceJWT, 
                 request: CreateClientRequest) -> AuthenticationResponse.TokensSet:
    client_id = request.client_id
    client_role = request.client_role
    expire_in = request.expire_in

    with tracer.start_as_current_span("validate-parameters") as span:
        span.set_attribute("client.id", client_id)
        span.set_attribute("client.role", client_role)
        span.set_attribute("token.expire_in", str(expire_in))

        try:
            role = ClientRole(client_role)
        except ValueError as e:
            span.set_status(Status(StatusCode.ERROR))
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=[ErrorSchema(error=ErrorCode.INVALID_PARAMETERS, extra=str(e))]
            )
    
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
        
    return AuthenticationResponse.TokensSet(
        access_token=access_token,
        refresh_token=refresh_token
    )
    
    
@router.post('/verify')
async def verify(service_jwt: ServiceJWT, request: VerifyRequest) -> ClientPayload:
    client_access_token = request.access_token
    
    with tracer.start_as_current_span("verify") as span:
        span.set_attribute("client.passed_access_token", mask_token(client_access_token))
        
        is_valid, body = check_token(token=client_access_token, 
                                     schema=ClientPayload, carrier=TokenBearer.CLIENT)
        span.add_event("the token has been processed")
        span.set_attribute("client.is_access_token_valid", is_valid)
        
        if is_valid:
            return body  # type: ignore[reportReturnType]
        else: 
            span.set_status(Status(StatusCode.ERROR))
            raise HTTPException(status_code=401, detail="Invalid access token")
    
    
@router.post('/update')
async def update(service_jwt: ServesUsers_ServiceJWT, request: UpdateClientRequest) -> AuthenticationResponse.TokensSet:
    client_access_token = request.client_access_token
    client_refresh_token = request.client_refresh_token
    expire_in = request.expire_in

    with tracer.start_as_current_span("tokens-up") as span:
        span.set_attribute(f"client.passed_access_token", mask_token(client_access_token))
        span.set_attribute(f"client.passed_refresh_token", mask_token(client_refresh_token))
        span.set_attribute("token.expire_in", str(expire_in))
        
        is_valid, body = tokens_up(  # type: ignore[reportAssignmentType]
            refresh_token=client_refresh_token, 
            access_token=client_access_token, 
            carrier=TokenBearer.CLIENT,
            expires_in=expire_in
        )
        span.add_event("the tokens have been processed")
        span.set_attribute("client.is_tokens_valid", is_valid)
        
        if is_valid:
            body: AuthenticationResponse.TokensSet
            span.set_attribute("client.created_access_token", mask_token(body.access_token))
            span.set_attribute("client.created_refresh_token", mask_token(body.refresh_token))
            return body
        else:
            span.set_status(Status(StatusCode.ERROR))
            raise HTTPException(status_code=401, detail=str(body)) 