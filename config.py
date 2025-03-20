import os
from dotenv import load_dotenv

load_dotenv()  

DB_CONFIG = {
    "host": os.getenv("DB_HOST", "database.cni44masspkf.eu-central-1.rds.amazonaws.com"),
    "port": os.getenv("DB_HOST", "3306"),
    "user": os.getenv("DB_USER", "admin"),
    "password": os.getenv("DB_PASSWORD", "adminpassworddb"),
    "database": os.getenv("DB_NAME", "app")
}

JWT_SECRET = os.getenv("JWT_SECRET", "supersecretkey")
