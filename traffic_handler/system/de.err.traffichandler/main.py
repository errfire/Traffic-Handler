#!/usr/bin/env python3
#ERR-FIRE
#Billel Meftah

from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from flask_caching import Cache
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
from urllib.parse import quote_plus, urlencode
from enum import Enum
from os import environ as env
from authlib.integrations.flask_client import OAuth
from cryptography.fernet import Fernet

import io
import sys
import platform
import re
import psutil
import configparser
import random
import string
import logging
import json
import base64
import os
import dotenv
import libconf



def de_traffichandler_main_logger():

    current_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(current_dir)


    log_dir = os.path.join("..", "..", "logs")
    data_dir = os.path.join("..", "..", "data")

    os.makedirs(log_dir, exist_ok=True)
    os.makedirs(data_dir, exist_ok=True)

    log_file_path = os.path.join(log_dir, "err_main.log")


    logging.basicConfig(
        format='%(asctime)s [%(levelname)s] > %(message)s ',
        filename=log_file_path,
        level=logging.INFO
    )

    logging.info('Logger started')
    logging.info(f'Logger Version {logging.__version__}')


de_traffichandler_main_logger()

def generate_alert_key(length=32):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))
def generate_secret_key(length=24):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(length))

def create_env_file(secret_key, alert_key):
    with open('.env', 'w') as env_file:
        env_file.write(f"SECRET_KEY={secret_key}\nALERTKEY={alert_key}")

if __name__ == "__main__":
    secret_key = generate_secret_key()
    alert_key = generate_alert_key()
    create_env_file(secret_key, alert_key)
    logging.info("Secret Key and Alert Key generated.")

conf_dir = os.path.join("..", "..", "conf")

key = Fernet.generate_key()
cipher_suite = Fernet(key)


smtp_config = configparser.ConfigParser()
smtp_config.read(conf_dir,"smtp_settings.cfg")

try:
    if not smtp_config.read(os.path.join(conf_dir, "smtp_settings.cfg")):
        logging.error("SMTP configuration file not found")

    if "SMTP" in smtp_config:
        logging.info("SMTP configuration successfully loaded")
    else:
        logging.error("SMTP configuration incorrect")

except Exception as e:
    logging.error(f"Error loading the SMTP configuration: {e}")

conf_file_path = os.path.join(conf_dir, "settings.cfg")
logging.info("Settings-Configuration files have been initialized")
with io.open(conf_file_path, encoding='utf-8') as f:
    try:
                load_dotenv()
                cfg = libconf.load(f)
                limiter = cfg.get('limiter')
                usessl = cfg.get('useSSL')
                Token = cfg.get('token')
                port = cfg.get('port')
                host = cfg.get('host')
                cert = cfg.get('cert')
                key = cfg.get('key')
                status = cfg.get('status')
                URL = cfg.get('url')
                City = cfg.get('city')
                ALERTKEY = os.getenv("ALERTKEY")
                login_basic = cfg.get('LOGINBASIC')

                if usessl == "True":
                    logging.info("SSL are enable, start secure Connection")
                    ssl_settings = (cert, key)
                elif usessl == "False":
                    logging.info("No SSL connection. Start unsecure.")
                    ssl_settings = None
                else:
                    logging.error("No valid value in usessl. Application is terminated.")
                    sys.exit(0)

                app = Flask(__name__, template_folder="static_sites")
                cache = Cache(app)
                cors = CORS(app)
                cors = CORS(app, resources={r"/*": {"origins": "*"}})

                load_dotenv('.extra_env_vars.env')
                app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
                app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
                bcrypt = Bcrypt(app)
                app.config['DEBUG'] = False
                app.config['TESTING'] = False
                app.logger.setLevel(logging.CRITICAL)
                logging.getLogger('werkzeug').setLevel(logging.ERROR)
                app.config['FLASK_ENV '] = "production"
                app.secret_key = os.getenv('SECRET_KEY')
                app.Version = os.getenv('Version')
                logging.info(f"ERR TrafficHandler Version: {app.Version}")

                ###########
                ###OAuth###
                ###########
                
                oauth_enabled = login_basic.lower() == 'false'
                oauth_disabled = login_basic.lower() == 'true'

                if oauth_enabled:
                    logging.info("OAuth is activate. ONLY OAuth login is currently available")

                    oauth = OAuth(app)
                    load_dotenv("iam.env")
                    oauth.register(
                        "auth0",
                        authservice=env.get("Auth-Service"),
                        client_id=env.get("IAM_CLIENT_ID"),
                        client_secret=env.get("IAM_CLIENT_SECRET"),
                        client_kwargs={
                            "scope": "openid profile email",
                        },
                        server_metadata_url=f'https://{env.get("IAM_DOMAIN")}/.well-known/openid-configuration'
                    )
                if oauth_disabled:
                    logging.info("Load  Basic Login modul")

                db = SQLAlchemy(app)
                logging.info("Database is ready")

                class Construction(db.Model):
                    id = db.Column(db.Integer, primary_key=True)
                    title = db.Column(db.String(100), nullable=False)
                    description = db.Column(db.Text, nullable=True)
                    strasse = db.Column(db.String(200), nullable=False)
                    plz = db.Column(db.String(8), nullable=False)
                    ort = db.Column(db.String(200), nullable=False)
                    start_date = db.Column(db.String(10), nullable=False)
                    end_date = db.Column(db.String(10), nullable=False)
                    latitude = db.Column(db.Float, nullable=True)
                    longitude = db.Column(db.Float, nullable=True)
                    type = db.Column(db.String(50), nullable=False)

                class UserRole(Enum):
                    ADMIN = "Admin"
                    EDITOR = "Editor"
                    VIEWER = "Viewer"

                class User(db.Model):
                    id = db.Column(db.Integer, primary_key=True)
                    username = db.Column(db.String(80), unique=True, nullable=False)
                    hashed_password = db.Column(db.String(128), nullable=False)
                    role = db.Column(db.Enum(UserRole), nullable=False,
                                     default=UserRole.VIEWER)


                class OAuthUser(db.Model):
                    id = db.Column(db.Integer, primary_key=True)
                    username = db.Column(db.String(80), unique=True, nullable=False)
                    email = db.Column(db.String(100), nullable=True)
                    emailverified = db.Column(db.Boolean, nullable=True, default=False)
                    accesstoken = db.Column(db.String(256), nullable=False)
                    role = db.Column(db.Enum(UserRole), nullable=False,default=UserRole.VIEWER)


                def get_user_and_constructions():
                    if 'user' not in session:
                        return None, None, None  

                    username = session.get('user')
                    recviedname = username.get('name')

                    if username:
                        user = OAuthUser.query.filter_by(username=recviedname).first()
                        user_role = user.role
                    else:
                        user = None
                        user_role = None

                    active_constructions = Construction.query.all()

                    return recviedname, user_role, active_constructions
                def create_user(username, hashed_password, role):
          
                    with app.app_context():
                      
                        existing_user = User.query.filter_by(username=username).first()
                        if existing_user:
                            logging.info(f"User '{username}' already exists.")
                        else:
                            hashed_password = bcrypt.generate_password_hash(hashed_password).decode('utf-8')

                            new_user = User(username=username, hashed_password=hashed_password, role=UserRole(role))
                            db.session.add(new_user)
                            db.session.commit()
                            logging.info(f"User '{username}' was created successfully with role '{role}'.")


                with app.app_context():
                    db.create_all()
                    create_user('poweruser', 'powerAdmin',UserRole.ADMIN.value)


                @app.errorhandler(Exception)
                def log_exceptions(error):
                    app.logger.error('Error: %s', error)
                    logging.error(error)
                    return "Internal Server Error", 500


                @app.route('/rest/health', methods=['GET'])
                def health_check():
                    return jsonify(status='OK')

                @app.route('/rest/v1/loginbasic/create_user', methods=['POST'])
                def create_user():
                    if 'username' not in session:
                        return redirect(url_for('login'))
                    if request.method == 'POST':
                        username = request.form['username']
                        password = request.form['password']
                        role = request.form.get('role')  

                        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

                        new_user = User(username=username, hashed_password=hashed_password, role=UserRole(role))
                        db.session.add(new_user)
                        db.session.commit()
                        logging.info(f"A new user has been created - {username}")

                    return render_template('success.html', Message=f"Der User {username} wurde erfolgreich angelegt", Version=app.Version, City=City)


                @app.route('/rest/v1/loginbasic/delete_user/<int:user_id>', methods=['GET'])
                def delete_user(user_id):
                    if 'username' not in session:
                        return redirect(url_for('login'))
                    user_to_delete = User.query.get_or_404(user_id)

                    if user_to_delete.username == 'poweruser':
                        error_message = f"Fehler - Der User {user_to_delete.username} darf nicht gelöscht werden."
                        logging.error(error_message)
                        return render_template('error.html', error_message=error_message, Version=app.Version,
                                               City=City)

                    db.session.delete(user_to_delete)
                    db.session.commit()
                    logging.info(f"The following user was deleted - {user_to_delete.username}")

                    return render_template('success.html', Message=f"Der User {user_to_delete.username} wurde erfolgreich gelöscht", Version=app.Version, City=City)


                @app.route('/rest/v1/loginbasic/change_password/<int:user_id>', methods=['GET', 'POST'])
                def change_password(user_id):
                    if 'username' not in session:
                        return redirect(url_for('login'))
                    user_to_change = User.query.get_or_404(user_id)

                    if request.method == 'POST':
                        new_password = request.form['new_password']
                        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
                        user_to_change.hashed_password = hashed_password
                        db.session.commit()
                        return render_template('success.html', Message="Das Passwort wurde erfolgreich geändert", Version=app.Version, City=City)

                    return render_template('change_password.html', user=user_to_change, Version=app.Version, City=City)


                @app.route('/rest/v1/loginbasic/change_role/<int:user_id>', methods=['GET', 'POST'])
                def change_role(user_id):
                    if 'username' not in session:
                        return redirect(url_for('login'))
                    user_to_change = User.query.get_or_404(user_id)

                    if request.method == 'POST':
                        new_role = request.form['new_role']
                        if new_role in ['VIEWER', 'EDITOR', 'ADMIN']:
                            user_to_change.role = new_role
                            db.session.commit()
                            return render_template('success.html', Message="Die Rolle wurde erfolgreich geändert",
                                                   Version=app.Version, City=City)

                    return render_template('change_role.html', user=user_to_change,Version=app.Version, City=City)


                @app.route('/dbconfig')
                def dbconfig():
                    if oauth_enabled:
                        username, user_role, active_constructions = get_user_and_constructions()

                        if username is None:
                            return redirect(url_for('login'))
                        error_message = "Fehler - Die Konfiguration von anderen Datenbanken folgt in einer späteren Version."
                        return render_template('error.html', error_message=error_message, Version=app.Version,
                                               City=City)

                    elif oauth_disabled:
                        if 'username' not in session:
                            return redirect(url_for('login'))
                        error_message = "Fehler - Die Konfiguration von anderen Datenbanken folgt in einer späteren Version."
                        return render_template('error.html', error_message=error_message, Version=app.Version, City=City)


                @app.route('/settings')
                def settings():
                    if oauth_enabled:
                        username, user_role, active_constructions = get_user_and_constructions()

                        if username is None:
                            return redirect(url_for('login'))
                        if user_role == UserRole.ADMIN:
                            smtp_settings = smtp_config['SMTP']
                            smtp_server = smtp_settings['smtp_server']
                            smtp_port = smtp_settings['smtp_port']
                            smtp_username = smtp_settings['smtp_username']

                            smtp_port = int(smtp_port)  

                            return render_template('settings.html',
                                                   Version=app.Version, City=City, smtp_settings=smtp_settings)
                        else:
                            error_message = "Fehler - Es scheint so, als hättest du für diesen Bereich keine Berechtigung."
                            return render_template('error.html', error_message=error_message, Version=app.Version,
                                                   City=City)

                    elif oauth_disabled:
                        if 'username' not in session:
                            return redirect(url_for('login'))
                        users = User.query.all()
                        username = session.get('username')
                        if username:
                            user = User.query.filter_by(username=username).first()
                            user_role = user.role

                        if user_role == UserRole.ADMIN:
                            all_users = User.query.all()

                            filtered_users = [user for user in all_users if user.username != 'poweruser']

                            smtp_settings = smtp_config['SMTP']
                            smtp_server = smtp_settings['smtp_server']
                            smtp_port = smtp_settings['smtp_port']
                            smtp_username = smtp_settings['smtp_username']

                            smtp_port = int(smtp_port)


                            return render_template('settings.html',
                                                   Version=app.Version, City=City, smtp_settings=smtp_settings)
                        else:
                            error_message = "Fehler - Es scheint so, als hättest du für diesen Bereich keine Berechtigung."
                            return render_template('error.html', error_message=error_message, Version=app.Version,
                                                   City=City)


                @app.route('/ereignisprotokoll')
                def ereignisse():
                    if oauth_enabled:
                        username, user_role, active_constructions = get_user_and_constructions()

                        if username is None:
                            return redirect(url_for('login'))
                        if user_role == UserRole.ADMIN:

                            log_data = []
                            logfile_path = '../../logs/err_main.log'
                            log_pattern = r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) \[(\w+)\] > (.+)'

                            with open(logfile_path, 'r') as logfile:
                                for line in logfile:
                                    match = re.match(log_pattern, line)
                                    if match:
                                        timestamp, log_level, message = match.groups()
                                        log_data.append({
                                            'timestamp': timestamp,
                                            'log_level': log_level,
                                            'message': message
                                        })

                            return render_template('ereignisprotokoll.html', log_data=log_data, Version=app.Version,
                                                   City=City)
                        else:
                            error_message = "Fehler - Es scheint so, als hättest du für diesen Bereich keine Berechtigung."
                            return render_template('error.html', error_message=error_message, Version=app.Version,
                                                   City=City)

                    elif oauth_disabled:
                        if 'username' not in session:
                            return redirect(url_for('login'))
                        users = User.query.all()
                        username = session.get('username')
                        if username:
                            user = User.query.filter_by(username=username).first()
                            user_role = user.role

                        if user_role == UserRole.ADMIN:
                            all_users = User.query.all()

                            filtered_users = [user for user in all_users if user.username != 'poweruser']
                        log_data = []
                        logfile_path = '../../logs/err_main.log'
                        log_pattern = r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) \[(\w+)\] > (.+)'

                        with open(logfile_path, 'r') as logfile:
                            for line in logfile:
                                match = re.match(log_pattern, line)
                                if match:
                                    timestamp, log_level, message = match.groups()
                                    log_data.append({
                                        'timestamp': timestamp,
                                        'log_level': log_level,
                                        'message': message
                                    })

                        return render_template('ereignisprotokoll.html', log_data=log_data, Version=app.Version, City=City)

                @app.route('/rest/v1/auth/oauth', methods=['GET', 'POST'])
                def oauthlogin():
                    if oauth_enabled:
                        return oauth.auth0.authorize_redirect(
                            redirect_uri=url_for("oauth_callback", _external=True))
                    elif oauth_disabled:
                        error_message = "Fehlerhafter Anmeldeversuch."
                        return render_template('login.html', error_message=error_message, Version=app.Version,
                                               City=City)


                @app.route('/rest/v1/auth/oauth/login')
                def oauth_login():
                    if oauth_enabled:
                        return render_template('oauth.html', authservice=env.get("Auth-Service"),Version=app.Version,
                                               City=City)
                    elif oauth_disabled:
                        return redirect(url_for('login'))



                @app.route('/rest/v1/auth/oauth/callback')
                def oauth_callback():
                    try:
                        if oauth_enabled:
                            oauth_response = oauth.auth0.authorize_access_token()


                            if oauth_response is not None:
                                userinfo = oauth_response.get('userinfo')
                                emailverified = userinfo.get('email_verified')
                                email = userinfo.get('email')
                                tokenentry= oauth_response.get('access_token')



                                if userinfo:
                                    username = userinfo.get('name')
                                    user = OAuthUser.query.filter_by(username=username).first()


                                    if user is None:
                                        logging.info("Login via OAuth user is created in database")
                                        new_user = OAuthUser(username=username, email=email, emailverified=emailverified, accesstoken=tokenentry)
                                        db.session.add(new_user)
                                        db.session.commit()


                                    session['user'] = userinfo

                                    return redirect(url_for('index'))
                        elif oauth_disabled:
                            error_message = "Fehlerhafter Anmeldeversuch."
                            return render_template('login.html', error_message=error_message, Version=app.Version,
                                                   City=City)
                        else:
                            error_message = "Keine Anmeldung möglich."
                            return render_template('oauth.html', error_message=error_message, Version=app.Version,
                                                   City=City)
                    except Exception as errorhandler:
                        logging.error(errorhandler)


                @app.route('/login/basic=1', methods=['GET', 'POST'])
                def fallback_basic_login():
                    try:
                        if oauth_disabled:
                            return redirect('/login')

                        elif oauth_enabled:
                                if request.method == 'POST':
                                    username = request.form.get('username')
                                    password = request.form.get('password')

                                    user = User.query.filter_by(username=username).first()

                                    if user and bcrypt.check_password_hash(user.hashed_password, password):
                                        session['username'] = username
                                        logging.info("Login via Fallback")
                                        return render_template('usersmanagment.html', Version=app.Version, City=City)

                                    error_message = "Die eingegebenen Daten stimmen nicht überein."
                                    logging.error(f"Incorrect login detected. Following user: {username}")
                                    return render_template('login.html', error_message=error_message, Version=app.Version, City=City)

                                return render_template('login.html', Version=app.Version, City=City)

                    except Exception as errorhandler:
                        logging.error(errorhandler)
                @app.route(f'/login', methods=['GET', 'POST'])
                def login():
                    try:
                        if oauth_disabled:
                            if request.method == 'POST':
                                username = request.form.get('username')
                                password = request.form.get('password')
                                user = User.query.filter_by(username=username).first()

                                if user and bcrypt.check_password_hash(user.hashed_password, password):
                                    session['username'] = username
                                    return redirect(url_for('index'))

                                error_message = "Die eingegebenen Daten stimmen nicht überein."
                                logging.error(f"Incorrect login detected. Following user: {username}")
                                return render_template('login.html', error_message=error_message, Version=app.Version,
                                                       City=City)

                            return render_template('login.html', Version=app.Version, City=City)
                        elif oauth_enabled:
                         
                                return redirect('/rest/v1/auth/oauth/login')
                    except Exception as errorhandler:
                        logging.error(errorhandler)


                @app.route('/logout', methods=['GET', 'POST'])
                def abmelden():
                    if oauth_enabled:
                        session.clear()
                        return redirect(
                            "https://" + env.get("IAM_DOMAIN")
                            + "/v2/logout?"
                            + urlencode(
                                {
                                    "returnTo": url_for("login", _external=True),
                                    "client_id": env.get("IAM_CLIENT_ID"),
                                },
                                quote_via=quote_plus,
                            )
                        )
                    if 'username' in session:
                        session.pop('username', None)
                        flash('Erfolgreich abgemeldet!', 'success')
                    else:
                        flash("NOT OK", 'danger')
                    return redirect(url_for('login'))


                @app.route('/save_smtp_settings', methods=['POST', 'GET'])
                def save_smtp_settings():
                    try:
                        if oauth_enabled:
                            username, user_role, active_constructions = get_user_and_constructions()

                            if username is None:
                                return redirect(url_for('login'))
                            if user_role == UserRole.ADMIN:
                    
                                smtp_server = request.form.get('smtp-server')
                                smtp_port = request.form.get('smtp-port')
                                smtp_username = request.form.get('smtp-username')
                                smtp_password = request.form.get('smtp-password')

                                encrypted_password = cipher_suite.encrypt(smtp_password.encode())
                                encoded_password = base64.b64encode(encrypted_password).decode()
     

   
                                smtp_config['SMTP'] = {
                                    'smtp_server': smtp_server,
                                    'smtp_port': smtp_port,
                                    'smtp_username': smtp_username,
                                    'smtp_password': encoded_password
                                }
                                conf_file_path = os.path.join(conf_dir, "smtp_settings.cfg")
                                with open(conf_file_path, 'w') as configfile:
                                    smtp_config.write(configfile)


                                return render_template('settings.html')
                        elif oauth_disabled:

                            if 'username' not in session:
                                return redirect(url_for('login'))
                            username = session.get('username')
                            if username:
                                user = User.query.filter_by(username=username).first()
                                user_role = user.role
                            if user_role == UserRole.ADMIN:
                                smtp_server = request.form.get('smtp-server')
                                smtp_port = request.form.get('smtp-port')
                                smtp_username = request.form.get('smtp-username')
                                smtp_password = request.form.get('smtp-password')

                                encrypted_password = cipher_suite.encrypt(smtp_password.encode())
                                encoded_password = base64.b64encode(encrypted_password).decode()

                                smtp_config['SMTP'] = {
                                    'smtp_server': smtp_server,
                                    'smtp_port': smtp_port,
                                    'smtp_username': smtp_username,
                                    'smtp_password': encoded_password
                                }

                                conf_file_path = os.path.join(conf_dir, "smtp_settings.cfg")
                                with open(conf_file_path, 'w') as configfile:
                                    smtp_config.write(configfile)

                                return render_template('settings.html')


                    except Exception as errorhandler:
                        logging.error(errorhandler)
                @app.route('/user-config')
                def users():
                    if oauth_enabled:
                        username, user_role, active_constructions = get_user_and_constructions()

                        if username is None:
                            return redirect(url_for('login'))

                        if user_role == UserRole.ADMIN:
                            all_users = User.query.all()
                            users = User.query.all()


                            filtered_users = [user for user in all_users if user.username != 'poweruser']

                            user_list = []
                            for user in filtered_users:
                                user_info = {'username': user.username}
                                user_list.append(user_info)

                            AuthUser = OAuthUser.query.all()

                            return render_template('usersmanagment.html', users=users, AuthUser=AuthUser, Version=app.Version, City=City)
                        else:
                            error_message = "Fehler - Es scheint so, als hättest du für diesen Bereich keine Berechtigung."
                            logging.error(f"The User {username} has no authorization.")
                            return render_template('error.html', error_message=error_message, Version=app.Version,
                                                   City=City)
                    elif oauth_disabled:
                        if 'username' not in session:
                            return redirect(url_for('login'))

                        users = User.query.all()
                        username = session.get('username')
                        if username:
                            user = User.query.filter_by(username=username).first()
                            user_role = user.role

                        if user_role == UserRole.ADMIN:
                            all_users = User.query.all()


                            filtered_users = [user for user in all_users if user.username != 'poweruser']
                            user_list = []
                            for user in filtered_users:
                                user_info = {'username': user.username}
                                user_list.append(user_info)

                            AuthUser = OAuthUser.query.all()
                            return render_template('usersmanagment.html', AuthUser=AuthUser,users=users, Version=app.Version, City=City)


                        error_message = "Fehler - Es scheint so, als hättest du für diesen Bereich keine Berechtigung."
                        logging.error(f"The User {username} has no authorization.")
                        return render_template('error.html', error_message=error_message, Version=app.Version, City=City)

                @app.route('/')
                @cache.cached(timeout=60)
                def index():
                    if oauth_enabled:
                        username, user_role, active_constructions = get_user_and_constructions()

                        if username is None:
                            return redirect(url_for('login'))

                        return render_template('index.html', constructions=active_constructions,
                                               Version=app.Version, username=username, City=City,
                                               user_role=user_role)
                    elif oauth_disabled:
                        if 'username' not in session:
                            return redirect(url_for(f'login'))

                        active_constructions = Construction.query.all()
                        username = session.get('username')
                        if username:
                            user = User.query.filter_by(username=username).first()
                            user_role = user.role

                        return render_template('index.html', constructions=active_constructions, Version=app.Version, username=username, City=City, user_role=user_role)


                @app.route('/rest/v1/get_constructions', methods=['GET'])
                def get_constructions():
                    if oauth_enabled:
                        username, user_role, active_constructions = get_user_and_constructions()

                        if username is None:
                            return redirect(url_for('login'))

                        constructions = Construction.query.all()
                        construction_list = []
                        for construction in constructions:
                            construction_info = {
                                'title': construction.title,
                                'strasse': construction.strasse,
                                'plz': construction.plz,
                                'ort': construction.ort,
                                'latitude': construction.latitude,
                                'longitude': construction.longitude,
                                'type': construction.type
                            }
                            construction_list.append(construction_info)
                        return jsonify(construction_list)

                    elif oauth_disabled:

                        if 'username' not in session:
                            return redirect(url_for('login'))
                        constructions = Construction.query.all()
                        construction_list = []
                        for construction in constructions:
                            construction_info = {
                                'title': construction.title,
                                'strasse': construction.strasse,
                                'plz': construction.plz,
                                'ort': construction.ort,
                                'latitude': construction.latitude,
                                'longitude': construction.longitude,
                                'type': construction.type
                            }
                            construction_list.append(construction_info)
                        return jsonify(construction_list)

                @app.route('/new_traffic_entry')
                @cache.cached(timeout=60)
                def new_traffic_entry():
                    if oauth_enabled:
                        username, user_role, active_constructions = get_user_and_constructions()

                        if username is None:
                            return redirect(url_for('login'))
                        return render_template('new_traffic_entry.html', Version=app.Version, City=City)

                    elif oauth_disabled:
                        if 'username' not in session:
                            return redirect(url_for('login'))
                        return render_template('new_traffic_entry.html', Version=app.Version, City=City)


                @app.route('/entry_revoke')
                @cache.cached(timeout=60)
                def entry_revoke():
                    if oauth_enabled:
                        username, user_role, active_constructions = get_user_and_constructions()

                        if username is None:
                            return redirect(url_for('login'))
                        active_constructions = Construction.query.all()
                        return render_template('entry_revoke.html', constructions=active_constructions,
                                               Version=app.Version)
                    elif oauth_disabled:
                        if 'username' not in session:
                            return redirect(url_for('login'))
                        active_constructions = Construction.query.all()
                        return render_template('entry_revoke.html',constructions=active_constructions, Version=app.Version)


                @app.route('/rest/v1/route/alert', methods=['GET'])
                def alert_route():
                    if oauth_enabled:
                        username, user_role, active_constructions = get_user_and_constructions()

                        if username is None:
                            return redirect(url_for('login'))

                        destination_coords = {
                            'data.latitude': 50.822942745215016,
                            'data.longitude': 6.13288970078409
                        }

                        return jsonify(destination_coords)

                    elif oauth_disabled:
                        if 'username' not in session:
                            return redirect(url_for('login'))
                        destination_coords = {
                            'data.latitude': 50.822942745215016,
                            'data.longitude': 6.13288970078409
                        }

                        return jsonify(destination_coords)


                @app.route('/rest/v1/external/maps', methods=['GET'])
                def interface_external():
                    if oauth_enabled:
                        username, user_role, active_constructions = get_user_and_constructions()

                        if username is None:
                            return redirect(url_for('login'))
                        constructions = Construction.query.all()

                        construction_list = []
                        for construction in constructions:
                            construction_info = {
                                'title': construction.title,
                                'address': construction.address,
                                'latitude': construction.latitude,
                                'longitude': construction.longitude,
                                'type': construction.type
                            }
                            construction_list.append(construction_info)

                        return jsonify(construction_list)

                    elif oauth_disabled:
                        if 'username' not in session:
                            return redirect(url_for('login'))


                        constructions = Construction.query.all()

                        construction_list = []
                        for construction in constructions:
                            construction_info = {
                                'title': construction.title,
                                'address': construction.address,
                                'latitude': construction.latitude,
                                'longitude': construction.longitude,
                                'type': construction.type
                            }
                            construction_list.append(construction_info)

                        return jsonify(construction_list)


                @app.route('/rest/v1/alertservice/generate_key', methods=['POST'])
                def generate_access_key():
                    if oauth_enabled:
                        username, user_role, active_constructions = get_user_and_constructions()

                        if username is None:
                            return redirect(url_for('login'))

                        if user_role == UserRole.ADMIN or user_role == UserRole.EDITOR:
                            logging.info("A new ALERTKEY is generated")

                            new_key = ''.join(random.choices(string.ascii_letters + string.digits, k=20))


                            dotenv.set_key(".env", "ALERTKEY", f"{new_key}")
                            logging.info("The new ALERTKEY has been created")

                            return redirect(url_for('successful_change'))

                        error_message = "Fehler - Es scheint so, als hättest du für diesen Vorgang keine Berechtigung."
                        logging.error(f"The User {username} has no authorization.")
                        return render_template('error.html', error_message=error_message)

                    elif oauth_disabled:
                        if 'username' not in session:
                            return redirect(url_for('login'))
                        username = session.get('username')
                        if username:
                            user = User.query.filter_by(username=username).first()
                            user_role = user.role

                        if user_role == UserRole.ADMIN or user_role == UserRole.EDITOR:
                            logging.info("A new ALERTKEY is generated")

                            new_key = ''.join(random.choices(string.ascii_letters + string.digits, k=20))


                            dotenv.set_key(".env", "ALERTKEY", f"{new_key}")
                            logging.info("The new ALERTKEY has been created")

                            return redirect(url_for('successful_change'))

                        error_message = "Fehler - Es scheint so, als hättest du für diesen Vorgang keine Berechtigung."
                        logging.error(f"The User {username} has no authorization.")
                        return render_template('error.html', error_message=error_message)

                @app.route('/rest/v1/alertservice/successfullkey', methods=['GET'])
                def successful_change():
                    if 'username' not in session:
                        return redirect(url_for('login'))
                    username = session.get('username')
                    if username:
                        user = User.query.filter_by(username=username).first()
                        user_role = user.role

                    if user_role == UserRole.ADMIN:
                     return render_template('alertkeychange.html', Version=app.Version, City=City)

                    error_message = "Fehler - Es scheint so, als hättest du für diesen Vorgang keine Berechtigung."
                    logging.error(f"The User {username} has no authorization.")
                    return render_template('error.html', error_message=error_message, Version=app.Version, City=City)

                @app.route('/alertservice')
                @cache.cached(timeout=60)
                def alertservice():
                    if oauth_enabled:
                        username, user_role, active_constructions = get_user_and_constructions()

                        if username is None:
                            return redirect(url_for('login'))

                        if user_role == UserRole.ADMIN:
                            Alertlink = f"[FQDN]:[PORT]/rest/v1/alertservice/{ALERTKEY}"
                            return render_template('alertservice.html', Version=app.Version, City=City,
                                                   ALERTKEY=ALERTKEY,
                                                   Alertlink=Alertlink)

                        error_message = "Fehler - Es scheint so, als hättest du für diesen Vorgang keine Berechtigung."
                        logging.error(f"The User {username} wir role {user_role} has no authorization.")
                        return render_template('error.html', error_message=error_message, Version=app.Version,
                                               City=City)
                    elif oauth_disabled:
                        if 'username' not in session:
                            return redirect(url_for('login'))
                        username = session.get('username')
                        if username:
                            user = User.query.filter_by(username=username).first()
                            user_role = user.role

                        if user_role == UserRole.ADMIN:
                            Alertlink = f"[FQDN]:[PORT]/rest/v1/alertservice/{ALERTKEY}"
                            return render_template('alertservice.html', Version=app.Version, City=City, ALERTKEY=ALERTKEY,
                                                   Alertlink=Alertlink)

                        error_message = "Fehler - Es scheint so, als hättest du für diesen Vorgang keine Berechtigung."
                        logging.error(f"The User {username} wir role {user_role} has no authorization.")
                        return render_template('error.html', error_message=error_message, Version=app.Version, City=City)

                DATA_DIRECTORY = os.path.join("..", "..", "data")
                def save_to_json_file(unit, keyword):
                    data = {
                        "unit": unit,
                        "keyword": keyword
                    }
                    filename = os.path.join(DATA_DIRECTORY, "alert.json")
                    with open(filename, "w") as json_file:
                        json.dump(data, json_file)
                    return filename


                @app.route(f'/rest/v1/alertservice/{ALERTKEY}', methods=['POST', 'GET'])
                def alertserv():
                    if request.method == 'POST':

                        logging.info("Receive new ALERT - POST")
                        data = request.get_json()
                        unit = data.get('unit')
                        keyword = data.get('keyword')
                        if unit and keyword:
                            save_to_json_file(unit, keyword)
                            return jsonify({'message': 'POST-Anfrage erfolgreich verarbeitet'})

                    elif request.method == 'GET':
                        logging.info("Receive new ALERT - GET")
                        unit = request.args.get('unit')
                        keyword = request.args.get('keyword')
                        if unit and keyword:
                            save_to_json_file(unit, keyword)
                            return jsonify({'message': 'GET-Anfrage erfolgreich verarbeitet'})

                    return jsonify({'message': 'NOT_OK'}), 405

                @app.route('/rest/v1/delete_construction/<int:construction_id>', methods=['GET', 'POST'])
                def delete_construction(construction_id):
                    if oauth_enabled:
                        username, user_role, active_constructions = get_user_and_constructions()

                        if username is None:
                            return redirect(url_for('login'))
                        if user_role == UserRole.ADMIN or user_role == UserRole.EDITOR:
                            construction = Construction.query.get_or_404(construction_id)
                            db.session.delete(construction)
                            db.session.commit()
                            logging.info(f"The following entry was deleted {construction_id}")
                            return redirect(url_for('entry_revoke'))
                        error_message = "Fehler - Es scheint so, als hättest du für diesen Vorgang keine Berechtigung."
                        logging.error(f"The User {username} has no authorization.")
                        return render_template('error.html', error_message=error_message)
                    elif oauth_disabled:
                        if 'username' not in session:
                            return redirect(url_for('login'))
                        username = session.get('username')
                        if username:
                            user = User.query.filter_by(username=username).first()
                            user_role = user.role

                        if user_role == UserRole.ADMIN or user_role == UserRole.EDITOR:
                            construction = Construction.query.get_or_404(construction_id)
                            db.session.delete(construction)
                            db.session.commit()
                            logging.info(f"The following entry was deleted {construction_id}")
                            return redirect(url_for('entry_revoke'))
                        error_message = "Fehler - Es scheint so, als hättest du für diesen Vorgang keine Berechtigung."
                        logging.error(f"The User {username} has no authorization.")
                        return render_template('error.html', error_message=error_message)

                @app.route('/rest/v1/add_construction', methods=['POST'])
                def add_construction():
                    if oauth_enabled:
                        username, user_role, active_constructions = get_user_and_constructions()

                        if username is None:
                            return redirect(url_for('login'))
                        if user_role == UserRole.ADMIN or user_role == UserRole.EDITOR:
                            title = request.form['title']
                            description = request.form['description']
                            strasse = request.form['strasse']
                            plz = request.form['plz']
                            ort = request.form['ort']
                            start_date = request.form['start_date']
                            end_date = request.form['end_date']
                            latitude = request.form['latitude']
                            longitude = request.form['longitude']
                            type = request.form['type']
                            new_construction = Construction(title=title, description=description, strasse=strasse,plz=plz,ort=ort,
                                                            start_date=start_date, end_date=end_date, latitude=latitude,
                                                            longitude=longitude, type=type)
                            db.session.add(new_construction)
                            db.session.commit()
                            logging.info(f"New traffic situation entered {new_construction}")

                            active_constructions = Construction.query.all()
                            return redirect(url_for('index'))

                        error_message = "Fehler - Es scheint so, als hättest du für diesen Vorgang keine Berechtigung."
                        logging.error(f"The User {username} has no authorization.")
                        return render_template('error.html', error_message=error_message)

                    elif oauth_disabled:
                        if 'username' not in session:
                            return redirect(url_for('login'))
                        username = session.get('username')
                        if username:
                            user = User.query.filter_by(username=username).first()
                            user_role = user.role

                        if user_role == UserRole.ADMIN or user_role == UserRole.EDITOR:
                            title = request.form['title']
                            description = request.form['description']
                            strasse = request.form['strasse']
                            plz = request.form['plz']
                            ort = request.form['ort']
                            start_date = request.form['start_date']
                            end_date = request.form['end_date']
                            latitude = request.form['latitude']
                            longitude = request.form['longitude']
                            type = request.form['type']
                            new_construction = Construction(title=title, description=description, strasse=strasse,plz=plz,ort=ort,
                                                            start_date=start_date, end_date=end_date, latitude=latitude, longitude=longitude, type=type)
                            db.session.add(new_construction)
                            db.session.commit()
                            logging.info(f"New traffic situation entered {new_construction}")

                            active_constructions = Construction.query.all()
                            return redirect(url_for('index'))
                        error_message = "Fehler - Es scheint so, als hättest du für diesen Vorgang keine Berechtigung."
                        logging.error(f"The User {username} has no authorization.")
                        return render_template('error.html', error_message=error_message)


                @app.route('/endpoints', methods=['GET'])
                def list_endpoints():
                    if oauth_enabled:
                        username, user_role, active_constructions = get_user_and_constructions()

                        if username is None:
                            return redirect(url_for('login'))
                        if user_role == UserRole.ADMIN:
                            routes = []
                            for rule in app.url_map.iter_rules():
                                if "static" not in rule.endpoint:
                                    route_info = {
                                        'url': rule.rule,
                                        'endpoint': rule.endpoint
                                    }
                                    routes.append(route_info)

                            return jsonify(endpoints=routes)

                    elif oauth_disabled:

                        if 'username' not in session:
                            return jsonify({'message': 'No authorization'}), 401
                        username = session.get('username')
                        if username:
                            user = User.query.filter_by(username=username).first()
                            user_role = user.role

                        if user_role == UserRole.ADMIN:
                            routes = []
                            for rule in app.url_map.iter_rules():
                                if "static" not in rule.endpoint:
                                    route_info = {
                                        'url': rule.rule,
                                        'endpoint': rule.endpoint
                                    }
                                    routes.append(route_info)

                            return jsonify(endpoints=routes)
                @app.route('/system')
                @cache.cached(timeout=60)
                def systemweb():
                    if oauth_enabled:
                        username, user_role, active_constructions = get_user_and_constructions()

                        if username is None:
                            return redirect(url_for('login'))
                        if user_role == UserRole.ADMIN:
                            memory = psutil.virtual_memory()
                            cpu_percent = psutil.cpu_percent()
                            system = platform.system()
                            versionpython = sys.version
                            disk_usage = psutil.disk_usage('.')
                            space_var = disk_usage.free / (1024 ** 3)
                            total_space = disk_usage.total / (1024 ** 3)
                            space = "{:.2f} GB".format(space_var)
                            totalspace = "{:.2f} GB".format(total_space)

                            return render_template('system.html', memory=memory, cpu_percent=cpu_percent, system=system,
                                                   space=space, totalspace=totalspace,
                                                   Version=app.Version, City=City)

                        error_message = "Fehler - Es scheint so, als hättest du für diesen Vorgang keine Berechtigung."
                        logging.error(f"The User {username} has no authorization.")
                        return render_template('error.html', error_message=error_message)
                    elif oauth_disabled:

                        if 'username' not in session:
                            return redirect(url_for('login'))
                        username = session.get('username')
                        if username:
                            user = User.query.filter_by(username=username).first()
                            user_role = user.role

                        if user_role == UserRole.ADMIN:

                           memory = psutil.virtual_memory()
                           cpu_percent = psutil.cpu_percent()
                           system = platform.system()
                           versionpython = sys.version
                           disk_usage = psutil.disk_usage('.')
                           space_var = disk_usage.free / (1024 ** 3)
                           total_space = disk_usage.total / (1024 ** 3)
                           space = "{:.2f} GB".format(space_var)
                           totalspace = "{:.2f} GB".format(total_space)

                           return render_template('system.html', memory=memory, cpu_percent=cpu_percent, system=system,
                                                   space=space, totalspace=totalspace, versionpython=versionpython, Version=app.Version, City=City)

                        error_message = "Fehler - Es scheint so, als hättest du für diesen Vorgang keine Berechtigung."
                        logging.error(f"The User {username} has no authorization.")
                        return render_template('error.html', error_message=error_message)
                    
                if __name__ == '__main__':
                    app.run(ssl_context=ssl_settings, host=host, port=port)



    except Exception as errorhandler:
        logging.error(errorhandler)
