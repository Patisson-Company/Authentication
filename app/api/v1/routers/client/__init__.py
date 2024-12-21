from fastapi import APIRouter
from .jwt import router as jwt_router

router = APIRouter()

router.include_router(jwt_router, prefix="/jwt")
