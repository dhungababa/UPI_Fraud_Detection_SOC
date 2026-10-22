import pandas as pd
import numpy as np
import time

print("Loading raw UPI transactions...")
df = pd.read_csv('../data/raw/upi_transactions.csv')

# 1. Convert timestamp to datetime and sort
print("Sorting data chronologically for time-series analysis...")
df['timestamp'] = pd.to_datetime(df['timestamp'])
df = df.sort_values(by=['sender_upi', 'timestamp'])
df = df.reset_index(drop=True)

# 2. Advanced Feature Engineering: Rolling Transaction Velocity
# This is exactly what FAANG companies use to detect fraud
print("Calculating 1-Hour Rolling Transaction Velocity...")

# We set the timestamp as the index so pandas can do rolling time windows
df = df.set_index('timestamp')

# Group by the sender, and calculate how many transactions they made in the last 1 hour (1H)
df['txn_count_1h'] = df.groupby('sender_upi')['transaction_id'].transform(
    lambda x: x.rolling('1h').count()
)

# Group by the sender, and calculate the total money they spent in the last 1 hour
df['txn_amount_1h'] = df.groupby('sender_upi')['amount'].transform(
    lambda x: x.rolling('1h').sum()
)

# Reset index to bring timestamp back as a column
df = df.reset_index()

# 3. Geolocation Distance Mock (Checking if location changed too fast)
# In a real project, we would use the Haversine formula on Lat/Lon.
# Here, we will just create a boolean flag if their location is different from their previous transaction.
print("Calculating Geolocation anomalies...")
df['prev_location'] = df.groupby('sender_upi')['location'].shift(1)
df['location_changed'] = np.where(
    df['prev_location'].isna(), 
    0, 
    np.where(df['location'] != df['prev_location'], 1, 0)
)
df = df.drop(columns=['prev_location'])

# Save the enriched dataset
print("Feature Engineering Complete!")
output_file = '../data/processed/upi_transactions_enriched.csv'
df.to_csv(output_file, index=False)
print(f"Saved highly advanced dataset to {output_file}")
