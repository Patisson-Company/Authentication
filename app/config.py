import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()

SERVICE_NAME = 'authentication'
SERVICE_HOST: str = os.getenv("SERVICE_HOST_")

JWT_KEY: str = os.getenv("JWT_KEY")
JWT_ALGORITHM: str = os.getenv("JWT_ALGORITHM")
JWT_EXPIRATION_SECONDS = int(os.getenv("JWT_EXPIRATION_SECONDS"))
JWT_EXPIRATION_TIME = timedelta(seconds=JWT_EXPIRATION_SECONDS) 

DATABASE_URL: str = os.getenv("DATABASE_URL")