FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .

# uvicorn main:app --host 0.0.0.0 --port 8080 --workers 17
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "3", "--log-level", "info", "--limit-max-requests", "10000"]


