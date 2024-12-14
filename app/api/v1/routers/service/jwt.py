from api.deps import ServiceJWT, SessionDep, security
from config import logger
from db.base import get_session
from db.crud import service_auth
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials
from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode
from patisson_request.errors import ErrorCode, ErrorSchema
from patisson_request.jwt_tokens import (ServiceAccessTokenPayload,
                                         TokenBearer, mask_token)
from patisson_request.roles import ServiceRole
from patisson_request.service_requests import AuthenticationRequest
from patisson_request.service_responses import (AuthenticationResponse,
                                                TokensSetResponse)
from patisson_request.services import Service
from tokens.jwt import (check_token, create_refresh_token,
                        create_service_token, tokens_up)

router = APIRouter()
tracer = trace.get_tracer(__name__)

@router.post('/create')
async def create_route(session: SessionDep, 
                 request: AuthenticationRequest.CreateService
                 ) -> TokensSetResponse:
    login = request.login
    password = request.password
    
    with tracer.start_as_current_span("service-authentication") as span:
        span.set_attribute("service.login", login)
        span.set_attribute("service.password", mask_token(password, visible_chars=2))
        async with get_session() as session:  # type: ignore[reportAssignmentType]
            is_valid, body = await service_auth(session, login, password)  # type: ignore[reportAssignmentType]
        span.add_event("the database request has been completed")
        span.set_attribute("db.query.service", str(body))
        
        if not is_valid:
            span.set_status(Status(StatusCode.ERROR))
            logger.warning(f'service {login} failed authentication: {body}')
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, 
                detail=[body.model_dump()]
            )
    
    with tracer.start_as_current_span("creating-tokens") as span:
        try:
            access_token = create_service_token(
                role=ServiceRole(str(body.role)),  # type: ignore[reportAttributeAccessIssue]
                service=Service(body.login)  # type: ignore[reportAttributeAccessIssue]
            )
        except ValueError as e:
            logger.warning(f'the {login} service tried to create a token with a non-existent role')
            span.set_status(Status(StatusCode.ERROR))
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=[ErrorSchema(error=ErrorCode.INVALID_PARAMETERS, extra=str(e)).model_dump()]
            )
            
        span.add_event("access token is ready")
        span.set_attribute("service.created_access_token", mask_token(access_token))
        
        refresh_token = create_refresh_token(
            sub=Service(body.login).name  # type: ignore[reportAttributeAccessIssue]
        )
        span.add_event("refresh token is ready")
        span.set_attribute("service.created_refresh_token", mask_token(refresh_token))
    
    logger.info(f'tokens have been successfully created for {login}')
    return TokensSetResponse(
        access_token=access_token,
        refresh_token=refresh_token
    )
        
        
@router.post('/verify')
async def verify_route(service_jwt: ServiceJWT, 
                 request: AuthenticationRequest.Verify
                 ) -> AuthenticationResponse.Verify:
    verified_service_jwt = request.access_token
    with tracer.start_as_current_span("verify") as span:
        span.set_attribute(f"service.verified_service_jwt", mask_token(str(verified_service_jwt)))
        
        is_valid, body = check_token(token=str(verified_service_jwt), 
                                     schema=ServiceAccessTokenPayload, 
                                     carrier=TokenBearer.SERVICE)
        span.add_event("the token has been processed")
        span.set_attribute("service.is_verified_service_jwt_valid", is_valid)
        
        if is_valid:
            logger.info(f'the {body.sub} token is valid, the verifying service {service_jwt.sub}')  # type: ignore[reportArgumentType]
            return AuthenticationResponse.Verify(is_verify=is_valid, payload=body, error=None)  # type: ignore[reportArgumentType]
        else:
            logger.warning(f'the token is not valid, the verifying service {service_jwt.sub}')  # type: ignore[reportArgumentType]
            return AuthenticationResponse.Verify(is_verify=is_valid, payload=None, error=body)  # type: ignore[reportArgumentType]


@router.post('/update')
async def update_route(service_jwt: ServiceJWT, 
                 request: AuthenticationRequest.UpdateService, 
                 credentials: HTTPAuthorizationCredentials = Depends(security)
                 ) -> TokensSetResponse:
    refresh_token = request.refresh_token

    # A token with the AnyStr type is required, not a ServicePayload (type of service_jwt)
    with tracer.start_as_current_span("tokens-up") as span:
        span.set_attribute("service.refresh_token", mask_token(str(refresh_token)))
        
        is_valid, body = tokens_up(  
            refresh_token=str(refresh_token), 
            access_token=credentials.credentials,  # binary service access token
            carrier=TokenBearer.SERVICE
            )
        span.add_event("the tokens has been processed")
        span.set_attribute("service.is_tokens_valid", is_valid)
        
        if is_valid:
            span.set_attribute("service.created_access_token", mask_token(body.access_token))  # type: ignore[reportAttributeAccessIssue]
            span.set_attribute("service.created_refresh_token", mask_token(body.refresh_token))  # type: ignore[reportAttributeAccessIssue]
            logger.info(f'the {service_jwt.sub} has successfully updated the tokens')
            return body  # type: ignore[reportReturnType]
        else:
            span.set_status(Status(StatusCode.ERROR))
            logger.warning(f'service {service_jwt.sub} was unable to update tokens: {body}')
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=[error.model_dump() for error in body]  # type: ignore[reportAttributeAccessIssue]
            )