# Sample Dockerfile for Flask backend
FROM python:3.10-slim

WORKDIR /app

# Install system dependencies (if needed)
RUN apt-get update && apt-get install -y build-essential && rm -rf /var/lib/apt/lists/*

# Copy requirements (if you have a requirements.txt)
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose port (Flask default)
EXPOSE 5000

# Set environment variables for Flask
ENV FLASK_APP=middleware10.py
ENV FLASK_RUN_HOST=0.0.0.0

# Run the Flask app
CMD ["flask", "run"]
