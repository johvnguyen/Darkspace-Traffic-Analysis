# Use an official Python base image
FROM python:3.12-slim

# Set the working directory in the container
WORKDIR /app

# Copy backend files
COPY backend/ /app/backend/

# Copy frontend files (static files)
COPY dashboard/ /app/dashboard/

# Install backend dependencies
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Expose the port your backend server runs on
EXPOSE 8081

WORKDIR /app/backend

# Command to run the backend server
CMD ["python", "server.py"]
#CMD ["uvicorn", "backend.server:app", "--host", "0.0.0.0", "--port", "8081"]