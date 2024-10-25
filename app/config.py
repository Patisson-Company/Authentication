import os
from datetime import timedelta

from dotenv import load_dotenv

load_dotenv()

SERVICE_NAME = 'authentication'
SERVICE_HOST: str = os.getenv("SERVICE_HOST_")  # type: ignore[reportArgumentType]

JWT_KEY: str = os.getenv("JWT_KEY")  # type: ignore[reportArgumentType]
JWT_ALGORITHM: str = os.getenv("JWT_ALGORITHM")  # type: ignore[reportArgumentType]
JWT_EXPIRATION_SECONDS = int(os.getenv("JWT_EXPIRATION_SECONDS"))  # type: ignore[reportArgumentType]
JWT_EXPIRATION_TIME = timedelta(seconds=JWT_EXPIRATION_SECONDS) 

DATABASE_URL: str = os.getenv("DATABASE_URL")  # type: ignore[reportArgumentType]
