#!/usr/bin/env python3
#ERR-FIRE
#Billel Meftah

from flask import Flask
from flask_caching import Cache
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
from authlib.integrations.flask_client import OAuth
from logger import initialize_logger
from key_generator import generate_secret_key,generate_alert_key, create_env_file
import os
import configparser
import logging
import io
import libconf
import sqlalchemy

initialize_logger()
def main():
    try:

        secret_key = generate_secret_key()
        alert_key = generate_alert_key()
        create_env_file(secret_key, alert_key)
        app.logger.debug("Keys generated! .env file created successfully.")
        app.logger.debug(f"Secret-Key: {secret_key}")
        app.logger.debug(f"Alert-Key: {alert_key}")
    except Exception as errorhandler:
        app.logger.error(f"Error: {errorhandler}")

app = Flask(__name__, template_folder="static_sites")
main()
cache = Cache(app)
cors = CORS(app, resources={r"/*": {"origins": "*"}})
bcrypt = Bcrypt(app)
conf_dir = os.path.join("..", "..", "conf")
load_dotenv()
load_dotenv('.extra_env_vars.env')
app.logger.info("Start Read config.ini File")
config = configparser.ConfigParser()
config.read("../../conf/config.ini")
app.logger.info("Finish read in")
app.config['SQLALCHEMY_DATABASE_URI'] = config.get('DEFAULT', 'DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
bcrypt = Bcrypt(app)
app.config['DEBUG'] = config.getboolean('DEFAULT', 'DEBUG')
app.config['TESTING'] = config.getboolean('DEFAULT', 'TESTING')
NoAuth="Fehler - Es scheint so, als hättest du für diesen Bereich keine Berechtigung."
if app.config['DEBUG']:
    app.logger.info("DEBUG Modus activate")
    app.logger.info("Please note that the DEBUG mode logs all information. Please only activate it for troubleshooting purposes.")
else:
    app.logger.info("DEBUG is not active")

UPLOAD_FOLDER = config.get('DEFAULT', 'UPLOAD_FOLDER')
ALLOWED_EXTENSIONS = set([config.get('DEFAULT', 'ALLOWED_EXTENSIONS')])
logging.getLogger('werkzeug').setLevel(config.get('DEFAULT', 'LOGGING_LEVEL'))
app.config['FLASK_ENV'] = config.get('DEFAULT', 'FLASK_ENV')
app.config['PDF_FOLDER'] = config.get('DEFAULT', 'PDF_FOLDER')
app.secret_key = os.getenv('SECRET_KEY')
app.Version = config.get('DEFAULT', 'VERSION')


app.logger.debug("Read Secret Key in Application")
app.logger.info(f"ERR TrafficHandler Version: {app.Version}")

conf_file_path = os.path.join(conf_dir, "settings.cfg")
app.logger.info("Open Settings.cfg - Read out Parameters")
with io.open(conf_file_path, encoding='utf-8') as f:
        load_dotenv()
        cfg = libconf.load(f)
        login_basic = cfg.get('LOGINBASIC')


oauth_enabled = login_basic.lower() == 'false'
oauth_disabled = login_basic.lower() == 'true'

if oauth_enabled:
    app.logger.info("OAuth is activate. ONLY OAuth login is currently available")
    oauth = OAuth(app)
    app.logger.info("Start read Configuration-File")
    config = configparser.ConfigParser()
    config.read('../../conf/iam.ini')
    Authservice= config.get('IAM', 'Auth-Service')
    ClientID=config.get('IAM', 'IAM_CLIENT_ID')
    IAMDomain=config.get("IAM", "IAM_DOMAIN")
    app.logger.info(f"Following Authservice Name: {Authservice}")
    oauth.register(
        "auth0",
        authservice=config.get('IAM', 'Auth-Service'),
        client_id=config.get('IAM', 'IAM_CLIENT_ID'),
        client_secret=config.get('IAM', 'IAM_CLIENT_SECRET'),
        client_kwargs={
            "scope": "openid profile email",
        },
        server_metadata_url=f'https://{config.get("IAM", "IAM_DOMAIN")}/.well-known/openid-configuration'
    )
    app.logger.info(f"Connection with following IAM: {IAMDomain}")

if oauth_disabled:
    app.logger.info("Load  Basic Login modul")

db = SQLAlchemy(app)
app.logger.info("Database is ready")
app.logger.info(f"DB-Version: {sqlalchemy.__version__}")
if not os.path.exists(app.config['PDF_FOLDER']):
    os.makedirs(app.config['PDF_FOLDER'])
    app.logger.debug("Create PDF Folder")

