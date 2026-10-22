import pandas as pd
from sqlalchemy import create_engine
import os
import time

# Get DATABASE_URL from Docker environment, fallback to local mapped port
DB_URL = os.getenv("DATABASE_URL", "postgresql://admin:password@localhost:5433/upi_fraud")

print(f"Connecting to PostgreSQL Database at {DB_URL}...")

# Add retry logic in case PostgreSQL is still booting up in Docker
connected = False
retries = 5
while not connected and retries > 0:
    try:
        engine = create_engine(DB_URL)
        connection = engine.connect()
        connection.close()
        connected = True
        print("Successfully connected to PostgreSQL!")
    except Exception as e:
        print(f"Database not ready yet, retrying in 5 seconds... ({retries} attempts left)")
        time.sleep(5)
        retries -= 1

if not connected:
    print("FATAL ERROR: Could not connect to PostgreSQL. Is Docker running?")
    exit(1)

print("Loading 500,000 rows from Enriched CSV...")
csv_path = "../data/processed/upi_transactions_enriched.csv"
df = pd.read_csv(csv_path)

print("Migrating Big Data into PostgreSQL (This may take a minute)...")
# Write to postgres in chunks to avoid memory crash
df.to_sql('transactions', engine, if_exists='replace', index=False, chunksize=10000)

print(f"Successfully migrated {len(df)} rows into the PostgreSQL 'transactions' table!")
