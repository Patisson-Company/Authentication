from api.deps import ServesUsers_ServiceJWT, ServiceJWT
from config import logger
from fastapi import APIRouter, HTTPException, status
from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode
from patisson_request.errors import ErrorCode, ErrorSchema
from patisson_request.jwt_tokens import (ClientAccessTokenPayload, TokenBearer,
                                         mask_token)
from patisson_request.roles import ClientRole
from patisson_request.service_requests import AuthenticationRequest
from patisson_request.service_responses import (AuthenticationResponse,
                                                TokensSetResponse)
from tokens.jwt import (check_token, create_client_token, create_refresh_token,
                        tokens_up)

router = APIRouter()
tracer = trace.get_tracer(__name__)

@router.post('/create')
async def create_route(service_jwt: ServesUsers_ServiceJWT, 
                 request: AuthenticationRequest.CreateClient
                 ) -> TokensSetResponse:
    client_id = request.client_id
    client_role = request.client_role
    expire_in = request.expire_in

    with tracer.start_as_current_span("validate-parameters") as span:
        span.set_attribute("client.id", client_id)
        span.set_attribute("client.role", client_role)
        span.set_attribute("token.expire_in", str(expire_in))

        try:
            role = ClientRole(client_role)
        except ValueError as e:
            logger.warning(f'the {service_jwt.sub} service tried to create a token with a non-existent role')
            span.set_status(Status(StatusCode.ERROR))
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=[ErrorSchema(error=ErrorCode.INVALID_PARAMETERS, extra=str(e)).model_dump()]
            )
    
    with tracer.start_as_current_span("creating-tokens") as span:
        access_token = create_client_token(
            role=role,
            client_id=client_id,
            expires_in=expire_in
        )
        span.add_event("access token is ready")
        span.set_attribute("client.created_access_token", mask_token(access_token))
        
        refresh_token = create_refresh_token(
            sub=client_id
        )
        span.add_event("refresh token is ready")
        span.set_attribute("service.created_refresh_token", mask_token(refresh_token))
        
    logger.info(f'tokens have been successfully created for {client_id} by {service_jwt.sub}')
    return TokensSetResponse(
        access_token=access_token,
        refresh_token=refresh_token
    )
    
    
@router.post('/verify')
async def verify_route(service_jwt: ServiceJWT, 
                 request: AuthenticationRequest.Verify
                 ) -> AuthenticationResponse.Verify:
    
    client_access_token = request.access_token
    with tracer.start_as_current_span("verify") as span:
        span.set_attribute("client.passed_access_token", mask_token(str(client_access_token)))
        
        is_valid, body = check_token(token=str(client_access_token), 
                                     schema=ClientAccessTokenPayload, 
                                     carrier=TokenBearer.CLIENT)
        span.add_event("the token has been processed")
        span.set_attribute("client.is_access_token_valid", is_valid)
        
        if is_valid:
            logger.info(f'the {body.sub} token is valid, the verifying service {service_jwt.sub}')  # type: ignore[reportArgumentType]
            return AuthenticationResponse.Verify(is_verify=is_valid, payload=body, error=None)  # type: ignore[reportArgumentType]
        else:
            logger.info(f'the token is not valid, the verifying service {service_jwt.sub}')  # type: ignore[reportArgumentType]
            return AuthenticationResponse.Verify(is_verify=is_valid, payload=None, error=body)  # type: ignore[reportArgumentType]
    
    
@router.post('/update')
async def update_route(service_jwt: ServesUsers_ServiceJWT, 
                 request: AuthenticationRequest.UpdateClient
                 ) -> TokensSetResponse:
    client_access_token = request.client_access_token
    client_refresh_token = request.client_refresh_token
    expire_in = request.expire_in

    with tracer.start_as_current_span("tokens-up") as span:
        span.set_attribute(f"client.passed_access_token", mask_token(str(client_access_token)))
        span.set_attribute(f"client.passed_refresh_token", mask_token(str(client_refresh_token)))
        span.set_attribute("token.expire_in", str(expire_in))
        
        is_valid, body = tokens_up(  # type: ignore[reportAssignmentType]
            refresh_token=str(client_refresh_token), 
            access_token=str(client_access_token), 
            carrier=TokenBearer.CLIENT,
            expires_in=expire_in
        )
        span.add_event("the tokens have been processed")
        span.set_attribute("client.is_tokens_valid", is_valid)
        
        if is_valid:
            span.set_attribute("client.created_access_token", mask_token(body.access_token))  # type: ignore[reportAttributeAccessIssue]
            span.set_attribute("client.created_refresh_token", mask_token(body.refresh_token))  # type: ignore[reportAttributeAccessIssue]
            logger.info(f'the {service_jwt.sub} has successfully updated the tokens for clients')
            return body  # type: ignore[reportReturnType]
        else:
            span.set_status(Status(StatusCode.ERROR))
            logger.warning(f'service {service_jwt.sub} was unable to update tokens for the client: {body}')
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=[error.model_dump() for error in body]  # type: ignore[reportAttributeAccessIssue]
            )