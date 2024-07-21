FROM python:3.11-slim as python-base

WORKDIR /app

COPY pyproject.toml poetry.lock ./

RUN pip install poetry \
    && poetry config virtualenvs.create false \
    && poetry install --no-dev

COPY . .

RUN python -m pip show uvicorn

CMD gunicorn main:app --reload --workers 1 --worker-class uvicorn.workers.UvicornWorker --bind=0.0.0.0:8000
