from typing import Literal
from db.models import Service
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from patisson_request.errors import ErrorSchema, ErrorCode

async def service_auth(session: AsyncSession, login: str, password: str) -> (
        tuple[Literal[True], Service] | tuple[Literal[False], ErrorSchema]
    ):
    '''
    Makes an asynchronous request to the database. 
    If there is a c passed login entry and the password is correct, 
    it will return Service (db.models), else it will return None
    '''
    try:
        stmt = select(Service).where(Service.login == login)
        result = await session.execute(stmt)
        service = result.scalars().first()
        
        if not service:
            return False, ErrorSchema(
                error=ErrorCode.INVALID_PARAMETERS,
                extra='the service login is incorrect'
            )
            
        if service and service.check_password(password):
            return True, service
        else:
            return False, ErrorSchema(
                error=ErrorCode.INVALID_PARAMETERS,
                extra='the service password is incorrect'
            )
        
    except ValueError:
        return False, ErrorSchema(
            error=ErrorCode.VALIDATE_ERROR,
            extra='the role is incorrect'
        )