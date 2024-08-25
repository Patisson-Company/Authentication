from sqlalchemy import Column, Integer, String
from db.base import Base
from core.security import Password


class Service(Base):
    __tablename__ = "services"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    login = Column(String, unique=True, index=True, nullable=False)
    password = Column(String, nullable=False)
    role = Column(String, nullable=False)

    def set_password(self, password: str) -> None:
        self.password = Password.hash(password)

    def check_password(self, password: str) -> bool:
        return Password.verify(password, self.password)