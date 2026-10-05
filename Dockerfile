FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv
WORKDIR /app
COPY pyproject.toml uv.lock README.md LICENSE ./
RUN uv sync --frozen --no-dev
COPY cryptoh/ ./cryptoh/
EXPOSE 8000
CMD ["uv", "run", "uvicorn", "cryptoh.web.server:app", "--host", "0.0.0.0", "--port", "8000"]
