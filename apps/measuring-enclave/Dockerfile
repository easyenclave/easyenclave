FROM cgr.dev/chainguard/cosign:latest AS cosign

FROM python:3.12-slim

WORKDIR /app

COPY --from=cosign /usr/bin/cosign /usr/local/bin/cosign

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8080

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]
