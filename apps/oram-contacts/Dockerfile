FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create data directory for SQLite
RUN mkdir -p /data

# Expose service port
EXPOSE 8080

# Run FastAPI service
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]
