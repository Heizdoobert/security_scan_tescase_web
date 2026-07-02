FROM mcr.microsoft.com/playwright/python:v1.40.0-jammy
WORKDIR /app
COPY . .
RUN pip install -e ".[dev]"
ENTRYPOINT ["python", "-m", "websec_test.main"]
