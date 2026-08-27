FROM python:3.12-slim

WORKDIR /app
COPY apps/api/pyproject.toml apps/api/README.md /app/
COPY apps/api/src /app/src
RUN pip install --no-cache-dir .

ENV PYTHONUNBUFFERED=1
EXPOSE 8000
CMD ["uvicorn", "aigov.main:app", "--host", "0.0.0.0", "--port", "8000"]
