from api.v1.routers import router as router_v1
from fastapi import APIRouter

router = APIRouter()

router.include_router(router_v1, prefix="/api/v1")