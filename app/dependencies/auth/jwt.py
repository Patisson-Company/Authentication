from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from patisson_tokens.jwt.schemas import ServicePayload
from tokens.jwt import check_token

security = HTTPBearer()

async def validate_service_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    is_valid, body = check_token(token=credentials.credentials, schema=ServicePayload)
    if is_valid:
        return body
    else:
        raise body
    
    