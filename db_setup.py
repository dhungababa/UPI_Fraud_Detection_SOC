import pandas as pd
from sqlalchemy import create_engine
import time
import os

print("Connecting to PostgreSQL...")
# Mapped to 5433 to avoid conflict with native PostgreSQL on 5432 (per docker-compose.yml)
engine = create_engine('postgresql://admin:password@localhost:5433/upi_fraud')

time.sleep(2)

base_dir = os.path.dirname(os.path.abspath(__file__))
csv_path = os.path.join(base_dir, 'data', 'raw', 'upi_transactions.csv')
if not os.path.exists(csv_path):
    # Fallback to current directory
    csv_path = os.path.join(base_dir, 'upi_transactions.csv')

print(f"Loading CSV from {csv_path}...")
df = pd.read_csv(csv_path)

print("Ingesting data into PostgreSQL 'transactions' table...")
# Ingest in chunks so it doesn't crash memory on large datasets
df.to_sql('transactions', engine, if_exists='replace', index=False, chunksize=10000)

print(f"Successfully migrated {len(df)} rows from CSV to Enterprise PostgreSQL Database!")
