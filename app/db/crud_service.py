from db.models.service import Service
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select


async def service_auth(session: AsyncSession, login: str, password: str) -> Service:
    stmt = select(Service).where(Service.login == login)
    result = await session.execute(stmt)
    service = result.scalars().first()
    if service and service.check_password(password):
        return service
    return None
