FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN useradd --create-home --shell /usr/sbin/nologin velloraq

COPY pyproject.toml README.md LICENSE NOTICE.md SECURITY.md ./
COPY velloraq ./velloraq
COPY app ./app
COPY serverless_security_scanner ./serverless_security_scanner
COPY examples ./examples

RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir ".[all]"

RUN mkdir -p /app/reports \
    && chown -R velloraq:velloraq /app

USER velloraq

EXPOSE 8000

CMD ["uvicorn", "velloraq.backend.api_server:app", "--host", "0.0.0.0", "--port", "8000"]
