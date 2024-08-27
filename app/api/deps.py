from typing import Annotated

from db.base import Session, get_session
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from patisson_errors import ErrorCode, ErrorSchema
from patisson_errors.fastapi import error
from patisson_tokens.jwt.schemas import ServicePayload
from patisson_tokens.jwt.types import TokenBearer
from patisson_tokens.roles import ServiceRole
from tokens.jwt import check_token

security = HTTPBearer()


def verify_service_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> ServicePayload | HTTPException:
    is_valid, body = check_token(token=credentials.credentials, schema=ServicePayload)
    if is_valid:
        return body
    else:
        raise body

def verify_serves_users__service_token(credentials: HTTPAuthorizationCredentials = Depends(security)
                                       ) -> ServicePayload | HTTPException:
    token = verify_service_token(credentials)
    service_role = ServiceRole(token.role)
    REQUIRED_PERM = [
        service_role.permissions.users_auth
        ]
    if not all(REQUIRED_PERM):
        raise error(
            status_code=status.HTTP_403_FORBIDDEN,
            errors=[ErrorSchema(error=ErrorCode.ACCESS_ERROR, extra=TokenBearer.SERVICE.value)]
            )
    return token
    
    
ServiceJWT = Annotated[ServicePayload, Depends(verify_service_token)]
ServesUsers_ServiceJWT = Annotated[ServicePayload, Depends(verify_serves_users__service_token)]

SessionDep = Annotated[Session, Depends(get_session)]