from api.deps import ServiceJWT, SessionDep, security
from api.v1.routers.schemes import (CreateServiceRequest, UpdateServiceRequest,
                                    VerifyRequest)
from db.base import get_session
from db.crud import service_auth
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials
from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode
from patisson_request.errors import ErrorCode, ErrorSchema
from patisson_request.jwt_tokens import ServiceAccessTokenPayload, TokenBearer
from patisson_request.service_responses import AuthenticationResponse
from patisson_request.roles import ServiceRole
from patisson_request.services import Service
from tokens.jwt import (check_token, create_refresh_token,
                        create_service_token, mask_token, tokens_up)

router = APIRouter()
tracer = trace.get_tracer(__name__)

@router.post('/create')
async def create(session: SessionDep, request: CreateServiceRequest
                 ) -> AuthenticationResponse.TokensSet:
    login = request.login
    password = request.password
    
    with tracer.start_as_current_span("service-authentication") as span:
        span.set_attribute("service.login", login)
        span.set_attribute("service.password", mask_token(password, visible_chars=2))
        async with get_session() as session:  # type: ignore[reportAssignmentType]
            service = await service_auth(session, login, password)  # type: ignore[reportAssignmentType]
        span.add_event("the database request has been completed")
        span.set_attribute("db.query.service", str(service))
        
        if not service:
            span.set_status(Status(StatusCode.ERROR))
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, 
                detail=[ErrorSchema(error=ErrorCode.BAD_CREDENTIALS)]
            )
    
    with tracer.start_as_current_span("creating-tokens") as span:
        access_token = create_service_token(
            role=ServiceRole(str(service.role)),
            service=Service(service.login)
        )
        span.add_event("access token is ready")
        span.set_attribute("service.created_access_token", mask_token(access_token))
        
        refresh_token = create_refresh_token(
            sub=Service(service.login).name
        )
        span.add_event("refresh token is ready")
        span.set_attribute("service.created_refresh_token", mask_token(refresh_token))
        
    return AuthenticationResponse.TokensSet(
        access_token=access_token,
        refresh_token=refresh_token
    )
        
@router.post('/verify')
async def verify(service_jwt: ServiceJWT, request: VerifyRequest) -> AuthenticationResponse.Verify:
        
    verified_service_jwt = request.access_token
    with tracer.start_as_current_span("verify") as span:
        span.set_attribute(f"service.verified_service_jwt", mask_token(verified_service_jwt))
        
        is_valid, body = check_token(token=verified_service_jwt, 
                                     schema=ServiceAccessTokenPayload, carrier=TokenBearer.SERVICE)
        span.add_event("the token has been processed")
        span.set_attribute("service.is_verified_service_jwt_valid", is_valid)
        
        if is_valid:
            return AuthenticationResponse.Verify(is_verify=is_valid, payload=body, error=None)  # type: ignore[reportArgumentType]
        else:
            return AuthenticationResponse.Verify(is_verify=is_valid, payload=None, error=body)  # type: ignore[reportArgumentType]


@router.post('/update')
async def update(service_jwt: ServiceJWT, request: UpdateServiceRequest, 
                 credentials: HTTPAuthorizationCredentials = Depends(security)
                 ) -> AuthenticationResponse.TokensSet:
    refresh_token = request.refresh_token

    # A token with the AnyStr type is required, not a ServicePayload (type of service_jwt)
    with tracer.start_as_current_span("tokens-up") as span:
        span.set_attribute("service.refresh_token", mask_token(refresh_token))
        
        is_valid, body = tokens_up(  # type: ignore[reportAssignmentType]
            refresh_token=refresh_token, 
            access_token=credentials.credentials,  # binary service access token
            carrier=TokenBearer.SERVICE
            )
        span.add_event("the tokens has been processed")
        span.set_attribute("service.is_tokens_valid", is_valid)
        
        if is_valid:
            body: AuthenticationResponse.TokensSet
            span.set_attribute("service.created_access_token", mask_token(body.access_token))
            span.set_attribute("service.created_refresh_token", mask_token(body.refresh_token))
            return body
        else:
            span.set_status(Status(StatusCode.ERROR))
            raise body  # type: ignore[reportGeneralTypeIssues]