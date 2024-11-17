import logging
import os
from datetime import timedelta

from dotenv import load_dotenv

root_path = os.path.join(os.path.dirname(__file__), '..')

load_dotenv(dotenv_path=os.path.join(root_path, '.env'))

SERVICE_NAME = 'authentication'
SERVICE_HOST: str = os.getenv("SERVICE_HOST_")  # type: ignore[reportArgumentType]

JWT_KEY: str = os.getenv("JWT_KEY")  # type: ignore[reportArgumentType]
JWT_ALGORITHM: str = os.getenv("JWT_ALGORITHM")  # type: ignore[reportArgumentType]
JWT_EXPIRATION_SECONDS = int(os.getenv("JWT_EXPIRATION_SECONDS"))  # type: ignore[reportArgumentType]
JWT_EXPIRATION_TIME = timedelta(seconds=JWT_EXPIRATION_SECONDS) 

DATABASE_URL: str = os.getenv("DATABASE_URL")  # type: ignore[reportArgumentType]


file_handler = logging.FileHandler(os.path.join(root_path, f'{SERVICE_NAME}.log'))
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(logging.Formatter(
    "%(levelname)s | %(asctime)s | %(module)s | %(funcName)s | %(message)s",
    datefmt='%Y-%m-%d %H:%M:%S'
))

logger = logging.getLogger(SERVICE_NAME)
logger.addHandler(file_handler)