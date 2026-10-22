FROM python:3.10-slim

WORKDIR /workspace

# Install system dependencies required for psycopg2
RUN apt-get update && apt-get install -y libpq-dev gcc

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# Add PostgreSQL adapter
RUN pip install psycopg2-binary sqlalchemy

# Copy the entire project structure
COPY . .

# Expose Streamlit port
EXPOSE 8501

# Command to run the Streamlit app
CMD ["streamlit", "run", "app/app.py", "--server.port=8501", "--server.address=0.0.0.0"]
