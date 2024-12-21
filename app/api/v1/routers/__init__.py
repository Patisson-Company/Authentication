from fastapi import APIRouter

from .client import router as client_router
from .service import router as service_router

router = APIRouter()

router.include_router(client_router, prefix="/client")
router.include_router(service_router, prefix="/service")
