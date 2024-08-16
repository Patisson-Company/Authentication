from fastapi import APIRouter, Depends

from dependencies.auth.jwt import validate_service_token

router = APIRouter()

@router.get('')
async def root(payload: dict = Depends(validate_service_token)):
    return {"message": "Access granted", "payload": payload}