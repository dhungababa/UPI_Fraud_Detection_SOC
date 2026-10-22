import pandas as pd
import numpy as np
from faker import Faker
import random
from datetime import datetime, timedelta

# Initialize Faker with Indian locale to generate realistic Indian names and locations
fake = Faker('en_IN')

# Configuration
NUM_TRANSACTIONS = 500000
FRAUD_RATIO = 0.01        # ~1% fraud to match the 99:1 imbalance on your resume

# UPI configuration
BANKS = ['@okicici', '@okhdfcbank', '@oksbi', '@ybl', '@paytm', '@apl']
MERCHANT_CATEGORIES = ['Groceries', 'Utilities', 'Electronics', 'Travel', 'Gaming', 'Crypto', 'Jewelry']

# Generate a pool of 5000 realistic returning users
print("Initializing user pool...", flush=True)
USER_POOL = [f"user{i}@{random.choice(BANKS)}" for i in range(5000)]

print(f"Generating {NUM_TRANSACTIONS} UPI transactions...", flush=True)

def generate_upi_id(name):
    # Convert "Devashish Sharma" to "devashish.sharma@okicici"
    clean_name = name.lower().replace(" ", ".")
    return f"{clean_name}{random.choice(BANKS)}"

data = []
start_date = datetime(2024, 1, 1)

for i in range(NUM_TRANSACTIONS):
    if i % 10000 == 0 and i > 0:
        print(f"Generated {i} records...", flush=True)

    # Generate realistic base data
    sender_name = fake.name()
    receiver_name = fake.name()
    
    sender_upi = random.choice(USER_POOL)
    receiver_upi = generate_upi_id(receiver_name) if random.random() > 0.3 else f"{fake.company().replace(' ','').lower()}@ybl"
    
    # 99% legitimate, 1% fraud
    is_fraud = 1 if random.random() < FRAUD_RATIO else 0
    
    # Logic to simulate REAL fraud patterns (Overlapping distributions)
    if is_fraud:
        # Fraudsters do large and small amounts
        amount = round(random.uniform(1000, 100000), 2)
        # Fraud happens mostly late night, but sometimes during the day
        hour = random.choice([0, 1, 2, 3, 4, 12, 14, 22, 23])
        # High-risk categories, but they also test stolen cards on groceries
        category = random.choice(['Gaming', 'Crypto', 'Jewelry', 'Groceries', 'Travel'])
    else:
        # Normal user behavior (but occasionally large amounts)
        amount = round(random.uniform(10, 25000), 2)
        # Normal daytime hours, but occasionally late night
        hour = random.randint(0, 23)
        category = random.choice(MERCHANT_CATEGORIES)
        
    # Generate timestamp
    minute = random.randint(0, 59)
    second = random.randint(0, 59)
    days_offset = random.randint(0, 180)
    
    txn_date = start_date + timedelta(days=days_offset, hours=hour, minutes=minute, seconds=second)
    
    # Build transaction record
    txn = {
        'transaction_id': fake.uuid4(),
        'timestamp': txn_date.strftime('%Y-%m-%d %H:%M:%S'),
        'sender_upi': sender_upi,
        'receiver_upi': receiver_upi,
        'amount': amount,
        'merchant_category': category,
        'device_type': random.choice(['Android', 'iOS']),
        'location': fake.city(),
        'is_fraud': is_fraud
    }
    
    data.append(txn)
    
    if (i + 1) % 10000 == 0:
        print(f"Generated {i + 1} records...")

# Convert to Pandas DataFrame
df = pd.DataFrame(data)

# Print strict imbalance stats to prove 99:1 ratio
print("\nDataset generated successfully!")
print("Fraud vs Legitimate breakdown:")
print(df['is_fraud'].value_counts(normalize=True) * 100)

# Save to CSV
output_file = '../data/raw/upi_transactions.csv'
df.to_csv(output_file, index=False)
print(f"\nData saved to {output_file}. Ready for XGBoost training!")
