from datetime import UTC, datetime, timedelta
from typing import AnyStr, Literal, Optional, TypeAlias, TypeVar, Union

import jwt
from core.config import (JWT_ALGORITHM, JWT_EXPIRATION_TIME, JWT_KEY,
                         SERVICE_NAME)
from fastapi import HTTPException, status
from patisson_errors.core import ErrorCode, ErrorSchema
from patisson_errors.fastapi import error
from patisson_tokens import ClientRole, Role, ServiceRole
from patisson_tokens.jwt.schemas import (ClientPayload, RefreshPayload,
                                         ServicePayload)
from patisson_tokens.jwt.types import TokenBearer, TokenType
from pydantic import ValidationError

SUB_SEPARATOR = '.'

PAYLOAD = TypeVar('PAYLOAD', bound=Union[ClientPayload, ServicePayload, RefreshPayload])
Seconds: TypeAlias = int


def create_client_token(role: Role, client_id: str, expires_in: Optional[Seconds] = None) -> bytes:
    expires_in_ = timedelta(seconds=expires_in) if expires_in else JWT_EXPIRATION_TIME 
    now = datetime.now(UTC)
    payload = ClientPayload(
        iss=SERVICE_NAME,
        sub=create_sub(bearer=TokenBearer.CLIENT, entity_id=client_id),
        exp=int((now + expires_in_).timestamp()),
        iat=int(now.timestamp()),
        role=role.name
    )
    return jwt.encode(payload.model_dump(), JWT_KEY, algorithm=JWT_ALGORITHM)


def create_service_token(role: Role, service_id: str, expires_in: Optional[Seconds] = None) -> bytes:
    expires_in_ = timedelta(seconds=expires_in) if expires_in else JWT_EXPIRATION_TIME
    now = datetime.now(UTC)
    payload = ServicePayload(
        iss=SERVICE_NAME,
        sub=create_sub(bearer=TokenBearer.SERVICE, entity_id=service_id),
        exp=int((now + expires_in_).timestamp()),
        iat=int(now.timestamp()),
        role=role.name
    )
    return jwt.encode(payload.model_dump(), JWT_KEY, algorithm=JWT_ALGORITHM)


def create_refresh_token(sub: str, expires_in: Optional[Seconds] = None) -> bytes:
    expires_in_ = timedelta(seconds=expires_in) if expires_in else JWT_EXPIRATION_TIME
    now = datetime.now(UTC)
    payload = RefreshPayload(
        iss=SERVICE_NAME,
        sub=sub,
        exp=int((now + expires_in_).timestamp()),
        iat=int(now.timestamp())
    )
    return jwt.encode(payload.model_dump(), JWT_KEY, algorithm=JWT_ALGORITHM)


def tokens_up(refresh_token: AnyStr, access_token: AnyStr, 
              schema: type[ClientPayload | ServicePayload],
              expires_in: Optional[Seconds] = None) -> (
                  tuple[Literal[True], tuple[bytes, bytes]] 
                  | tuple[Literal[False], HTTPException]
                  ):
    carrier = _find_carrier(schema)
    is_access_token_valid, access_body = check_token(
        token=access_token, 
        schema=schema, 
        carrier=f'{carrier}.{TokenType.ACCESS.value}',
        _return_ErrorSchema=True
        )
    is_refresh_token_valid, refresh_body = check_token(
        token=refresh_token, 
        schema=RefreshPayload, 
        carrier=f'{carrier}.{TokenType.REFRESH.value}',
        _return_ErrorSchema=True
        )
    
    errors_report = []
    if not is_access_token_valid:
        errors_report.append(access_body) 
    if not is_refresh_token_valid:
        errors_report.append(refresh_body)
    try:
        assert access_body.sub == refresh_body.sub
    except AssertionError:
        errors_report.append(ErrorSchema(error=ErrorCode.JWT_INVALID))  # ErrorCode.JWT_SUB_NOT_EQUAL
    if len(errors_report) > 0:
        return False, error(
            status_code=status.HTTP_400_BAD_REQUEST,
            errors=errors_report
        )  
    
    if carrier == TokenBearer.CLIENT.value:
        new_access_token = create_client_token(
            role=ClientRole(access_body.role),
            client_id=access_body.sub.split(SUB_SEPARATOR)[1],
            expires_in=expires_in
        )
    elif carrier == TokenBearer.SERVICE.value:
        new_access_token = create_service_token(
            role=ServiceRole(access_body.role),
            service_id=access_body.sub.split(SUB_SEPARATOR)[1],
            expires_in=expires_in
        )
    new_refresh_token = create_refresh_token(
        sub=access_body.sub,
        expires_in=expires_in
    )
    
    return True, (new_access_token, new_refresh_token)
ServiceRole.SERVES_USERS

def check_token(token: AnyStr, schema: type[PAYLOAD], carrier: Optional[str] = None,
                _return_ErrorSchema: bool = False) -> (
                    tuple[Literal[True], PAYLOAD] 
                    | tuple[Literal[False], HTTPException]
                    | tuple[Literal[False], ErrorSchema]
                    ):
    carrier = _find_carrier(schema, carrier)
    flag = False
    try:
        body = schema(
            **jwt.decode(str(token), JWT_KEY, algorithms=[JWT_ALGORITHM])
        )
        flag = True
    except jwt.ExpiredSignatureError:
        error_ = ErrorSchema(
            error=ErrorCode.JWT_EXPIRED,
            extra=carrier
            )   
        status_code = status.HTTP_403_FORBIDDEN
    except jwt.InvalidTokenError:
        error_ = ErrorSchema(
            error=ErrorCode.JWT_INVALID,
            extra=carrier
            )   
        status_code = status.HTTP_401_UNAUTHORIZED
    except ValidationError:
        error_ = ErrorSchema(
            error=ErrorCode.JWT_INVALID,
            extra=carrier
        )
        status_code = status.HTTP_400_BAD_REQUEST
    finally:
        if flag: 
            return True, body
        if _return_ErrorSchema:
            return False, error_
        return False, error(
            status_code=status_code,
            errors=[error_]
        )


def create_sub(bearer: TokenBearer, entity_id: str) -> str:
    return f'{bearer.value}{SUB_SEPARATOR}{entity_id}'        
        
        
def _find_carrier(schema: type[PAYLOAD], carrier: Optional[str] = None) -> str | None:
    if not carrier:
        if schema == ServicePayload: return TokenBearer.SERVICE.value
        elif schema == ClientPayload: return TokenBearer.CLIENT.value
    else: return carrier