from datetime import UTC, datetime, timedelta
from typing import AnyStr, Literal, Optional, TypeAlias, TypeVar, Union

import jwt
from config import JWT_ALGORITHM, JWT_EXPIRATION_TIME, JWT_KEY, SERVICE_NAME
from fastapi import HTTPException, status
from patisson_request.errors import ErrorCode, ErrorSchema
from patisson_request.jwt_tokens import (ClientPayload, RefreshPayload,
                                         ServicePayload, TokenBearer,
                                         TokenType)
from patisson_request.service_responses import AuthenticationResponse
from patisson_request.service_roles import ClientRole, Role, ServiceRole
from pydantic import ValidationError

SUB_SEPARATOR = '.'

PAYLOAD = TypeVar('PAYLOAD', bound=Union[ClientPayload, ServicePayload, RefreshPayload])
Seconds: TypeAlias = int


def create_client_token(role: Role, client_id: str, expires_in: Optional[Seconds] = None) -> str:
    '''
    Creates a jwt token for the client.
    
    If expire_in is set to None, the default value will be used.
    '''
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


def create_service_token(role: Role, service_id: str, expires_in: Optional[Seconds] = None) -> str:
    '''
    Creates a jwt token for the service.
    
    If expire_in is set to None, the default value will be used.
    '''
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


def create_refresh_token(sub: str, expires_in: Optional[Seconds] = None) -> str:
    '''
    Creates a refresh token for a client or service.
    
    If expire_in is set to None, the default value will be used.
    
    To pass a sub, use create_sub() from the same module.
    '''
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
              carrier: TokenBearer, expires_in: Optional[Seconds] = None) -> (
                  tuple[Literal[True], AuthenticationResponse.TokensSet] 
                  | tuple[Literal[False], HTTPException]
                  ):
    '''
    Checks access and refresh tokens, and if they are valid, 
    returns True with the first argument and tuple with a pair of new tokens. 
    
    If the passed tokens are not valid, 
    it returns False with the first argument and HTTPException with the second.
    '''
    is_access_token_valid, access_body = check_token(
        token=access_token, 
        schema=ClientPayload if carrier == TokenBearer.CLIENT else ServicePayload, 
        carrier=carrier,
        _return_ErrorSchema=True
        )
    is_refresh_token_valid, refresh_body = check_token(
        token=refresh_token, 
        schema=RefreshPayload, 
        carrier=carrier,
        _return_ErrorSchema=True
        )
    
    errors_report: list[ErrorSchema] = []
    if not is_access_token_valid:
        errors_report.append(access_body)   # type: ignore[reportArgumentType]
    if not is_refresh_token_valid:
        errors_report.append(refresh_body)  # type: ignore[reportArgumentType]
    try:
        assert access_body.sub == refresh_body.sub  # type: ignore[reportAttributeAccessIssue]
    except AssertionError:
        errors_report.append(ErrorSchema(error=ErrorCode.JWT_SUB_NOT_EQUAL))
    except AttributeError:  # AttributeError: 'ErrorSchema' object has no attribute 'sub'
        pass
    if len(errors_report) > 0:
        return False, HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=[error.model_dump() for error in errors_report]
        )  
    
    if carrier == TokenBearer.CLIENT:
        new_access_token = create_client_token(
            role=ClientRole(access_body.role),  # type: ignore[reportAttributeAccessIssue]
            client_id=access_body.sub.split(SUB_SEPARATOR)[1],  # type: ignore[reportAttributeAccessIssue]
            expires_in=expires_in
        )
    elif carrier == TokenBearer.SERVICE:
        new_access_token = create_service_token(
            role=ServiceRole(access_body.role),  # type: ignore[reportAttributeAccessIssue]
            service_id=access_body.sub.split(SUB_SEPARATOR)[1],  # type: ignore[reportAttributeAccessIssue]
            expires_in=expires_in
        )
    new_refresh_token = create_refresh_token(
        sub=access_body.sub,  # type: ignore[reportAttributeAccessIssue]
        expires_in=expires_in
    )
    
    return True, AuthenticationResponse.TokensSet(
        access_token=new_access_token,
        refresh_token=new_refresh_token
    )


def check_token(token: AnyStr, schema: type[PAYLOAD], carrier: TokenBearer,
                _return_ErrorSchema: bool = False) -> (
                    tuple[Literal[True], PAYLOAD] 
                    | tuple[Literal[False], HTTPException]
                    | tuple[Literal[False], ErrorSchema]
                    ):
    '''
    Verifies the token. If the token has passed verification, 
    it returns True with the first argument 
    and the payload of the token with the second argument.
    
    If the token fails verification, it returns False with the first argument 
    and HttpException with the second argument.
    
    If _return_ErrorSchema=True and the token is not valid, 
    it returns False with the first argument 
    and ErrorSchema (patisson_errors.core) with the second.
    '''
    flag = False
    try:
        body = schema(
            **jwt.decode(str(token), JWT_KEY, algorithms=[JWT_ALGORITHM])
        )
        flag = True
    except jwt.ExpiredSignatureError:
        error_ = ErrorSchema(
            error=ErrorCode.JWT_EXPIRED if carrier == TokenBearer.SERVICE 
            else ErrorCode.CLIENT_JWT_EXPIRED
            )   
        status_code = status.HTTP_403_FORBIDDEN
    except jwt.InvalidTokenError:
        error_ = ErrorSchema(
            error=ErrorCode.JWT_INVALID if carrier == TokenBearer.SERVICE 
            else ErrorCode.CLIENT_JWT_INVALID
            )   
        status_code = status.HTTP_401_UNAUTHORIZED
    except ValidationError:
        error_ = ErrorSchema(
            error=ErrorCode.JWT_INVALID if carrier == TokenBearer.SERVICE 
            else ErrorCode.CLIENT_JWT_INVALID
        )
        status_code = status.HTTP_400_BAD_REQUEST
    finally:
        if flag: 
            return True, body  # type: ignore[reportReturnType]
        if _return_ErrorSchema:
            return False, error_
        return False, HTTPException(
            status_code=status_code,
            detail=[error_.model_dump()]
        )


def create_sub(bearer: TokenBearer, entity_id: str) -> str:
    '''
    Use this to create a sub for tokens.
    '''
    return f'{bearer.value}{SUB_SEPARATOR}{entity_id}'        
        

def mask_token(token: str, visible_chars: int = 4) -> str:
    '''
    Closes the token * except for the last characters.
    '''
    if len(token) <= visible_chars:
        return token
    masked_part = '*' * (len(token) - visible_chars)
    visible_part = token[-visible_chars:]
    return f"{masked_part}{visible_part}"
