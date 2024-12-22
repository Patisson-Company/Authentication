"""
Authentication Utilities Module.

This module provides functions and utilities for handling authentication tasks
within the authentication service. While primarily designed to authenticate
services and clients using tokens (JWT), it is extensible to support other
authentication mechanisms in the future.

Key Functions:
    - `create_client_token`: Generates a JWT token for client authentication.
    - `create_service_token`: Generates a JWT token for service authentication.
    - `create_refresh_token`: Generates a refresh token for renewing access tokens.
    - `tokens_up`: Validates and updates access and refresh tokens.
    - `check_token`: Validates a token and extracts its payload if valid.

Features:
    - Support for both service and client authentication via bearer tokens.
    - Modular design to accommodate additional token schemas or alternative
      authentication methods in the future.
    - Token validation with detailed error reporting using `ErrorSchema`.
    - Logging of authentication events for debugging and auditing purposes.

Usage:
    This module is intended for use within the authentication service to verify
    and issue tokens. It can also be extended to authenticate external services
    and clients via APIs or other integrations.

"""

from datetime import UTC, datetime, timedelta
from typing import AnyStr, Literal, Optional, TypeAlias, TypeVar

import jwt
from config import JWT_ALGORITHM, JWT_EXPIRATION_TIME, JWT_KEY, SERVICE_NAME, logger
from patisson_request.errors import ErrorCode, ErrorSchema
from patisson_request.jwt_tokens import (
    BaseAccessTokenPayload,
    BaseTokenPayload,
    ClientAccessTokenPayload,
    RefreshTokenPayload,
    ServiceAccessTokenPayload,
    TokenBearer,
    TokenType,
)
from patisson_request.roles import Role
from patisson_request.service_responses import TokensSetResponse
from patisson_request.services import Service
from pydantic import ValidationError

SUB_SEPARATOR = "."

PAYLOAD = TypeVar("PAYLOAD", bound=BaseTokenPayload)
Seconds: TypeAlias = int


def create_client_token(role: Role, client_id: str, expires_in: Optional[Seconds] = None) -> str:
    """
    Generate a JWT token for a client.

    Args:
        role (Role): The role associated with the token.
        client_id (str): The unique identifier of the client.
        expires_in (Optional[Seconds]): Token expiration time in seconds.
            If not specified, the default expiration time is used.

    Returns:
        str: A signed JWT token for the client.

    Raises:
        ValueError: If any required parameter is invalid.

    Notes:
        Logs a debug message when the token is successfully created.
    """
    expires_in_ = timedelta(seconds=expires_in) if expires_in else JWT_EXPIRATION_TIME
    now = datetime.now(UTC)
    payload_model = ClientAccessTokenPayload
    payload_model.model_rebuild()
    payload = payload_model(
        type=TokenType.ACCESS,
        bearer=TokenBearer.CLIENT,
        iss=SERVICE_NAME,
        sub=client_id,
        exp=int((now + expires_in_).timestamp()),
        iat=int(now.timestamp()),
        role=role,
    )
    logger.debug(f"a client token has been created ({payload})")
    return jwt.encode(payload.model_dump(), JWT_KEY, algorithm=JWT_ALGORITHM)


def create_service_token(role: Role, service: Service, expires_in: Optional[Seconds] = None) -> str:
    """
    Generate a JWT token for a service.

    Args:
        role (Role): The role associated with the token.
        service (Service): The service identifier for which the token is created.
        expires_in (Optional[Seconds]): Token expiration time in seconds.
            If not specified, the default expiration time is used.

    Returns:
        str: A signed JWT token for the service.

    Raises:
        ValueError: If any required parameter is invalid.

    Notes:
        Logs a debug message when the token is successfully created.
    """
    expires_in_ = timedelta(seconds=expires_in) if expires_in else JWT_EXPIRATION_TIME
    now = datetime.now(UTC)
    payload_model = ServiceAccessTokenPayload[Service]
    payload_model.model_rebuild()
    payload = payload_model(
        type=TokenType.ACCESS,
        bearer=TokenBearer.SERVICE,
        iss=SERVICE_NAME,
        sub=service,
        exp=int((now + expires_in_).timestamp()),
        iat=int(now.timestamp()),
        role=role,
    )
    logger.debug(f"a service token has been created ({payload})")
    return jwt.encode(payload.model_dump(), JWT_KEY, algorithm=JWT_ALGORITHM)


def create_refresh_token(sub: str, expires_in: Optional[Seconds] = None) -> str:
    """
    Generate a refresh token for a client or service.

    Args:
        sub (str): The subject of the token, typically created using the `create_sub()` function
            from the same module.
        expires_in (Optional[Seconds]): Token expiration time in seconds.
            If not specified, the default expiration time is used.

    Returns:
        str: A signed refresh token.

    Raises:
        ValueError: If any required parameter is invalid.

    Notes:
        Logs a debug message when the token is successfully created.
    """
    expires_in_ = timedelta(seconds=expires_in) if expires_in else JWT_EXPIRATION_TIME
    now = datetime.now(UTC)
    payload_model = RefreshTokenPayload
    payload_model.model_rebuild()
    payload = payload_model(
        type=TokenType.REFRESH,
        iss=SERVICE_NAME,
        sub=sub,
        exp=int((now + expires_in_).timestamp()),
        iat=int(now.timestamp()),
    )
    logger.debug(f"a refresh token has been created ({payload})")
    return jwt.encode(payload.model_dump(), JWT_KEY, algorithm=JWT_ALGORITHM)


def tokens_up(
    refresh_token: AnyStr, access_token: AnyStr, carrier: TokenBearer, expires_in: Optional[Seconds] = None
) -> tuple[Literal[True], TokensSetResponse] | tuple[Literal[False], list[ErrorSchema]]:
    """
    Verify and update access and refresh tokens.

    Args:
        refresh_token (AnyStr): The refresh token to validate.
        access_token (AnyStr): The access token to validate.
        carrier (TokenBearer): Indicates the token type (`TokenBearer.CLIENT` or `TokenBearer.SERVICE`).
        expires_in (Optional[Seconds]): The expiration time for the new tokens.
            If not specified, the default expiration time is used.

    Returns:
        tuple: A tuple where:
            - The first element is a boolean indicating success (`True`) or failure (`False`).
            - The second element is either:
                - `TokensSetResponse` containing new access and refresh tokens on success.
                - A list of `ErrorSchema` instances indicating validation errors on failure.

    Raises:
        AssertionError: If the `sub` fields of the access and refresh tokens do not match.
        AttributeError: If a token validation error prevents accessing the `sub` attribute.

    Notes:
        Logs the errors if the tokens are invalid.
        On success, logs the creation of new tokens for the specified carrier.
    """
    is_access_token_valid, access_body = check_token(
        token=access_token,
        schema=ClientAccessTokenPayload if carrier == TokenBearer.CLIENT else ServiceAccessTokenPayload,
        carrier=carrier,
    )  # type: ignore[reportAssignmentType]
    is_refresh_token_valid, refresh_body = check_token(
        token=refresh_token, schema=RefreshTokenPayload, carrier=carrier
    )  # type: ignore[reportAssignmentType]

    errors_report: list[ErrorSchema] = []
    if not is_access_token_valid:
        errors_report.append(access_body)  # type: ignore[reportArgumentType]
    if not is_refresh_token_valid:
        errors_report.append(refresh_body)  # type: ignore[reportArgumentType]
    try:
        assert access_body.sub == refresh_body.sub  # type: ignore[reportAttributeAccessIssue]
    except AssertionError:
        errors_report.append(ErrorSchema(error=ErrorCode.JWT_SUB_NOT_EQUAL))
    except AttributeError:  # AttributeError: 'ErrorSchema' object has no attribute "sub"
        pass
    if len(errors_report) > 0:
        logger.debug(f"errors: {errors_report}")
        return False, errors_report

    access_body: BaseAccessTokenPayload
    refresh_body: RefreshTokenPayload
    if carrier == TokenBearer.CLIENT:
        new_access_token = create_client_token(
            role=access_body.role, client_id=access_body.sub, expires_in=expires_in
        )
    elif carrier == TokenBearer.SERVICE:
        new_access_token = create_service_token(
            role=access_body.role, service=access_body.sub, expires_in=expires_in
        )
    new_refresh_token = create_refresh_token(sub=access_body.sub, expires_in=expires_in)
    logger.debug(f"tokens have been successfully updated for {carrier}")
    return True, TokensSetResponse(access_token=new_access_token, refresh_token=new_refresh_token)


def check_token(
    token: AnyStr, schema: type[PAYLOAD], carrier: TokenBearer
) -> tuple[Literal[True], PAYLOAD] | tuple[Literal[False], ErrorSchema]:
    """
    Validate a token and return its payload if valid.

    Args:
        token (AnyStr): The JWT token to validate.
        schema (type[PAYLOAD]): The expected payload schema for validation.
        carrier (TokenBearer): Indicates the token type (`TokenBearer.CLIENT` or `TokenBearer.SERVICE`).

    Returns:
        tuple: A tuple where:
            - The first element is a boolean indicating validity (`True` for valid, `False` for invalid).
            - The second element is either:
                - The decoded payload (`PAYLOAD`) if the token is valid.
                - An `ErrorSchema` instance describing the error if the token is invalid.

    Raises:
        jwt.ExpiredSignatureError: If the token's signature has expired.
        jwt.InvalidTokenError: If the token is invalid or tampered with.
        ValidationError: If the payload does not match the expected schema.

    Notes:
        Logs whether the token is valid or invalid. If invalid, the error details are logged.
    """
    flag = False
    try:
        body = schema(**jwt.decode(str(token), JWT_KEY, algorithms=[JWT_ALGORITHM]))
        flag = True
    except jwt.ExpiredSignatureError:
        error_ = ErrorSchema(
            error=ErrorCode.JWT_EXPIRED if carrier == TokenBearer.SERVICE else ErrorCode.CLIENT_JWT_EXPIRED
        )
    except jwt.InvalidTokenError:
        error_ = ErrorSchema(
            error=ErrorCode.JWT_INVALID if carrier == TokenBearer.SERVICE else ErrorCode.CLIENT_JWT_INVALID
        )
    except ValidationError:
        error_ = ErrorSchema(
            error=ErrorCode.JWT_INVALID if carrier == TokenBearer.SERVICE else ErrorCode.CLIENT_JWT_INVALID
        )
    finally:
        if flag:
            logger.debug(f"the token is valid ({body})")
            return True, body  # type: ignore[reportReturnType]  # noqa: B012
        else:
            logger.debug(f"the token is not valid ({error_})")
            return False, error_  # noqa: B012
