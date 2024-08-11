import asyncio

from databases import Database
from sqlalchemy import MetaData
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

DATABASE_URL = "postgresql+asyncpg://patisson:123456@localhost:5432/patisson_authentication"

database = Database(DATABASE_URL)
metadata = MetaData()

engine = create_async_engine(DATABASE_URL, echo=True, future=True)
Base = declarative_base()

async_session = sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False
)

async def get_session():
    async with async_session() as session:
        yield session
        
def _db_init():
    async def create_tables():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    asyncio.run(create_tables())