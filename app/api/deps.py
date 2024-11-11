from typing import Annotated

from db.base import get_session
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode
from patisson_request.errors import ErrorCode, ErrorSchema
from patisson_request.jwt_tokens import ServiceAccessTokenPayload, TokenBearer
from sqlalchemy.orm import Session
from tokens.jwt import check_token, mask_token

security = HTTPBearer()
tracer = trace.get_tracer(__name__)


def verify_service_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> ServiceAccessTokenPayload | HTTPException:
    with tracer.start_as_current_span("verify-service-token") as span:
        token = credentials.credentials
        span.set_attribute("service.access_token", mask_token(token))
        
        is_valid, body = check_token(token=token, schema=ServiceAccessTokenPayload, carrier=TokenBearer.SERVICE)
        span.add_event("the token has been processed")
        span.set_attribute("service.is_access_token_valid", is_valid)
        
        if is_valid:
            return body  # type: ignore[reportReturnType]
        else:
            span.set_status(Status(StatusCode.ERROR))
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=[body.model_dump()]
                )


def verify_serves_users_service_token(token: ServiceAccessTokenPayload = Depends(verify_service_token)
                                       ) -> ServiceAccessTokenPayload | HTTPException:
    with tracer.start_as_current_span("checking-access-rights") as span:
        span.set_attribute("service.role", token.role.name)
        REQUIRED_PERM = [
            token.role.permissions.users_auth
            ]
        if not all(REQUIRED_PERM):
            span.set_status(Status(StatusCode.ERROR))
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=[ErrorSchema(
                        error=ErrorCode.ACCESS_ERROR, 
                        extra=TokenBearer.SERVICE.value).model_dump()
                        ]
                )
        return token
    
    
ServiceJWT = Annotated[ServiceAccessTokenPayload, Depends(verify_service_token)]
ServesUsers_ServiceJWT = Annotated[ServiceAccessTokenPayload, Depends(verify_serves_users_service_token)]

SessionDep = Annotated[Session, Depends(get_session)]