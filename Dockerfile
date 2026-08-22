FROM python:3.11-slim

# Install system dependencies (including OpenSSL dev for yara-python)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libmagic1 \
    libfuzzy-dev \
    libssl-dev \
    libmagic-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Create uploads directory
RUN mkdir -p uploads

EXPOSE 8000

CMD ["python", "app.py"]
