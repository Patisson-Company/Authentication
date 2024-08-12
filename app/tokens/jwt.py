from datetime import UTC, datetime, timedelta

import jwt
import patisson_tokens
import pydantic

from app.core.config import (JWT_ALGORITHM, JWT_EXPIRATION_TIME, JWT_KEY,
                             SERVICE_NAME)


def create_client_token(sub: str, role: patisson_tokens.user_role.UserRole, 
                        expires_in: timedelta = JWT_EXPIRATION_TIME) -> bytes:
    now = datetime.now(UTC)
    payload = patisson_tokens.jwt.schemas.ClientPayload(
        iss=SERVICE_NAME,
        sub=sub,
        exp=int((now + expires_in).timestamp()),
        iat=int(now.timestamp()),
        role=role.value
    )
    return jwt.encode(payload.model_dump(), JWT_KEY, algorithm=JWT_ALGORITHM)

def create_service_token(sub: str, expires_in: timedelta = JWT_EXPIRATION_TIME) -> bytes:
    now = datetime.now(UTC)
    payload = patisson_tokens.jwt.schemas.ServicePayload(
        iss=SERVICE_NAME,
        sub=sub,
        exp=int((now + expires_in).timestamp()),
        iat=int(now.timestamp())
    )
    return jwt.encode(payload.model_dump(), JWT_KEY, algorithm=JWT_ALGORITHM)

def create_refresh_token(sub: str, expires_in: timedelta = JWT_EXPIRATION_TIME) -> bytes:
    now = datetime.now(UTC)
    payload = patisson_tokens.jwt.schemas.RefreshPayload(
        iss=SERVICE_NAME,
        sub=sub,
        exp=int((now + expires_in).timestamp()),
        iat=int(now.timestamp())
    )
    return jwt.encode(payload.model_dump(), JWT_KEY, algorithm=JWT_ALGORITHM)

def tokens_up(refresh_token: bytes, access_token: bytes, 
                         expires_in: timedelta = JWT_EXPIRATION_TIME) -> tuple[bytes, bytes]:
    try:
        access_payload_mapping = jwt.decode(access_token, JWT_KEY, algorithms=[JWT_ALGORITHM])
        refresh_payload_mapping = jwt.decode(refresh_token, JWT_KEY, algorithms=[JWT_ALGORITHM])
    except jwt.InvalidSignatureError as e:
        ...  # log level: WARNING
        raise jwt.InvalidSignatureError(e)
    
    refresh_payload = patisson_tokens.jwt.schemas.RefreshPayload(**refresh_payload_mapping)
    if refresh_payload.exp < datetime.now(UTC).timestamp():
        raise ValueError("Refresh token expired")
    
    try:
        access_payload = patisson_tokens.jwt.schemas.ClientPayload(**access_payload_mapping)
        new_access_token = create_client_token(
            sub=access_payload.sub,
            role=patisson_tokens.user_role.UserRole(access_payload.role),
            expires_in=expires_in
        )
    except pydantic.ValidationError:
        access_payload = patisson_tokens.jwt.schemas.ServicePayload(**access_payload_mapping)
        new_access_token = create_service_token(
            sub=access_payload.sub,
            expires_in=expires_in
        )
    
    new_refresh_token = create_refresh_token(
        sub=refresh_payload.sub,
        expires_in=expires_in
    )
    
    return (new_access_token, new_refresh_token)