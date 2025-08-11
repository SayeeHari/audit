import os
from dotenv import load_dotenv
import pymysql

load_dotenv()

try:
    conn = pymysql.connect(
        host=os.getenv('DB_HOST'),
        user=os.getenv('DB_USER'),
        password=os.getenv('DB_PASS'),
        database=os.getenv('DB_NAME')
    )
    print("✅ MySQL connection successful!")
    conn.close()
except Exception as e:
    print("❌ MySQL connection failed:", e)
