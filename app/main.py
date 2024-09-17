from api import router
import config
from fastapi import FastAPI

from patisson_appLauncher.fastapi_app_launcher import UvicornFastapiAppLauncher


app = FastAPI(title=config.SERVICE_NAME)
        
        
if __name__ == "__main__":
    app_launcher = UvicornFastapiAppLauncher(app, router,
                        service_name=config.SERVICE_NAME,
                        host=config.SERVICE_HOST)
    app_launcher.add_sync_consul_health_path()
    app_launcher.consul_register()
    app_launcher.add_jaeger()
    app_launcher.include_router()
    app_launcher.app_run()