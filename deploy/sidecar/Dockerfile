FROM python:3.11-slim

WORKDIR /app

COPY pyproject.toml .
COPY src/regista/ src/regista/
COPY migrations/ migrations/

RUN pip install --no-cache-dir ".[sidecar]"

ENV REGISTA_BIND=0.0.0.0:8080

EXPOSE 8080

CMD ["python", "-m", "regista.sidecar"]
