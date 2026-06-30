FROM python:3.11-slim
WORKDIR /app
COPY . .
RUN pip install -e ".[dev]"
ENTRYPOINT ["python", "-m", "websec_test.main"]
