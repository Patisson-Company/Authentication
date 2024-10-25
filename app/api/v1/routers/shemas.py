from typing import Optional

from pydantic import BaseModel
from tokens.jwt import Seconds


class CreateClientRequest(BaseModel):
    client_id: str
    client_role: str
    expire_in: Optional[Seconds] 
    
class CreateServiceRequest(BaseModel):
    login: str
    password: str
    
class VerifyRequest(BaseModel):
    access_token: str

class UpdateClientRequest(BaseModel):
    client_access_token: str
    client_refresh_token: str
    expire_in: Optional[Seconds]
    
class UpdateServiceRequest(BaseModel):
    refresh_token: str