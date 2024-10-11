FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "${PORT:-8080}"]

# gcloud builds submit --tag gcr.io/[PROJECT-ID]/openid-provider
# gcloud run deploy --image gcr.io/[PROJECT-ID]/openid-provider --platform managed
