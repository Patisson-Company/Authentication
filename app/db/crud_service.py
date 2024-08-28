from db.models.service import Service
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select


async def service_auth(session: AsyncSession, login: str, password: str) -> Service | None:
    '''
    Makes an asynchronous request to the database. 
    If there is a c passed login entry and the password is correct, 
    it will return Service (db.models), else it will return None
    '''
    stmt = select(Service).where(Service.login == login)
    result = await session.execute(stmt)
    service = result.scalars().first()
    if service and service.check_password(password):
        return service