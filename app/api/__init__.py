from fastapi import APIRouter
from api.v1.routers import router as router_v1

router = APIRouter()

router.include_router(router_v1, prefix="/api/v1")