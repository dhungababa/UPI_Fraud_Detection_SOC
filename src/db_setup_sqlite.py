import pandas as pd
from sqlalchemy import create_engine

print("Connecting to Local Enterprise SQLite Database...")
engine = create_engine('sqlite:///../data/processed/upi_fraud.db')

print("Loading Enriched CSV...")
df = pd.read_csv('../data/processed/upi_transactions_enriched.csv')

print("Ingesting data into SQLite 'transactions' table...")
# Ingest in chunks so it doesn't crash memory on 1M rows
df.to_sql('transactions', engine, if_exists='replace', index=False, chunksize=10000)

print(f"Successfully migrated {len(df)} rows from CSV to SQLite Database!")
