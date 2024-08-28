from typing import Annotated

from db.base import Session, get_session
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode
from patisson_errors import ErrorCode, ErrorSchema
from patisson_errors.fastapi import error
from patisson_tokens.jwt.schemas import ServicePayload
from patisson_tokens.jwt.types import TokenBearer
from patisson_tokens.roles import ServiceRole
from tokens.jwt import check_token, mask_token

security = HTTPBearer()
tracer = trace.get_tracer(__name__)

def verify_service_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> ServicePayload | HTTPException:
    with tracer.start_as_current_span("verify-service-token") as span:
        token = credentials.credentials
        span.set_attribute("service.access_token", mask_token(token))
        
        is_valid, body = check_token(token=token, schema=ServicePayload)
        span.add_event("the token has been processed")
        span.set_attribute("service.is_access_token_valid", is_valid)
        
        if is_valid:
            return body
        else:
            span.set_status(Status(StatusCode.ERROR))
            raise body


def verify_serves_users__service_token(token: ServicePayload = Depends(verify_service_token)
                                       ) -> ServicePayload | HTTPException:
    with tracer.start_as_current_span("checking-access-rights") as span:
        service_role = ServiceRole(token.role)
        span.set_attribute("service.role", service_role.name)
        REQUIRED_PERM = [
            service_role.permissions.users_auth
            ]
        if not all(REQUIRED_PERM):
            span.set_status(Status(StatusCode.ERROR))
            raise error(
                status_code=status.HTTP_403_FORBIDDEN,
                errors=[ErrorSchema(error=ErrorCode.ACCESS_ERROR, extra=TokenBearer.SERVICE.value)]
                )
        return token
    
    
ServiceJWT = Annotated[ServicePayload, Depends(verify_service_token)]
ServesUsers_ServiceJWT = Annotated[ServicePayload, Depends(verify_serves_users__service_token)]

SessionDep = Annotated[Session, Depends(get_session)]