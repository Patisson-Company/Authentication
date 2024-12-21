from typing import Self

from db.base import Base
from passlib.context import CryptContext
from sqlalchemy import Column, Integer, String

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class Service(Base):
    __tablename__ = "services"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    login = Column(String, unique=True, index=True, nullable=False)
    password = Column(String, nullable=False)
    role = Column(String, nullable=False)

    def set_password(self, password: str) -> Self:
        self.password = pwd_context.hash(password)
        return self

    def check_password(self, password: str) -> bool:
        return pwd_context.verify(password, str(self.password))
