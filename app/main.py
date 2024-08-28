from api import router
from core import config
from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from opentelemetry import trace
from opentelemetry.exporter.jaeger.thrift import JaegerExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.sdk.resources import SERVICE_NAME, Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from patisson_errors.fastapi import validation_exception_handler

trace.set_tracer_provider(
    TracerProvider(
        resource=Resource.create({SERVICE_NAME: config.SERVICE_NAME})
    )
)
jaeger_exporter = JaegerExporter()
trace.get_tracer_provider().add_span_processor(
    BatchSpanProcessor(jaeger_exporter)
)

app = FastAPI(title=SERVICE_NAME)
FastAPIInstrumentor.instrument_app(app) 
app.include_router(router, prefix="/api")
app.add_exception_handler(RequestValidationError, validation_exception_handler)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=config.SERVICE_HOST, port=config.SERVICE_PORT)