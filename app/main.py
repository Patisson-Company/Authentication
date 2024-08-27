from api import router
from core.config import SERVICE_NAME as SERVICE_NAME_
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
        resource=Resource.create({SERVICE_NAME: SERVICE_NAME_})
    )
)
jaeger_exporter = JaegerExporter(
    agent_host_name="localhost",
    agent_port=6831,
)
trace.get_tracer_provider().add_span_processor(
    BatchSpanProcessor(jaeger_exporter)
)

app = FastAPI(title=SERVICE_NAME)
FastAPIInstrumentor.instrument_app(app) 
app.include_router(router, prefix="/api")
app.add_exception_handler(RequestValidationError, validation_exception_handler)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)