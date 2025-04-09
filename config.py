import os
from helper_functions import validate_env

variables =  ["SECRET_KEY", "DATABASE_URL", "EMAIL_USERNAME", "EMAIL_PASSWORD"]
validate_env(variables)

SECRET_KEY = os.getenv("SECRET_KEY")
SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL")
MAIL_SERVER = "smtp.gmail.com"
MAIL_PORT = 587
MAIL_USE_TLS = True
MAIL_USERNAME = os.getenv("EMAIL_USERNAME")
MAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
MAIL_DEFAULT_SENDER = MAIL_USERNAME