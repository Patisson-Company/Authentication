from fastapi import FastAPI
from core.config import SERVICE_NAME
from api import router

app = FastAPI(title=SERVICE_NAME)
 
app.include_router(router, prefix="/api")
 
# @app.get("/")
# def read_root():
#     return SERVICE_NAME

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)