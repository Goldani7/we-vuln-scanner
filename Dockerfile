# Goldani Scanner (wvs). Build:  docker build -t wvs .
# CLI:  docker run --rm wvs -t https://example.com --rich
# API:  docker run --rm -p 8000:8000 -e WVS_API_KEY=changeme --entrypoint uvicorn wvs api.main:app --host 0.0.0.0
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY scanner ./scanner
COPY api ./api
RUN pip install ".[api]" && useradd --create-home --uid 10001 wvs
USER wvs
ENTRYPOINT ["wvs"]
CMD ["--help"]
