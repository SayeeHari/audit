import os
from dotenv import load_dotenv

load_dotenv()
print(os.getenv('DB_USER'), os.getenv('DB_PASS'))
