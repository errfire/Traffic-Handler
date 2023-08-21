#!/usr/bin/env python3
#ERR-FIRE
#Billel Meftah

from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_caching import Cache
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
from enum import Enum


import io
import sys
import platform
import psutil
import random
import string
import logging
import json
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
        format='%(asctime)s (Python) [%(levelname)s] - [%(funcName)s] > %(message)s ',
        filename=log_file_path,
        level=logging.INFO
    )

    logging.info('Logger started')

de_traffichandler_main_logger()

def generate_secret_key(length=24):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(length))

def create_env_file(secret_key, alert_key):
    with open('.env', 'w') as env_file:
        env_file.write(f"SECRET_KEY={secret_key}\nALERTKEY={alert_key}")

if __name__ == "__main__":
    secret_key = generate_secret_key()
    alert_key = generate_secret_key()
    create_env_file(secret_key, alert_key)
    logging.info("Secret Key and Alert Key generated and saved to .env file.")

conf_dir = os.path.join("..", "..", "conf")


conf_file_path = os.path.join(conf_dir, "settings.cfg")
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


                app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
                app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
                bcrypt = Bcrypt(app)
                app.config['DEBUG'] = False
                app.config['TESTING'] = False
                app.config['FLASK_ENV '] = "production"
                app.secret_key = os.getenv('SECRET_KEY')
                app.Version = os.getenv('Version')
                logging.info(f"ERR Traffic Handler Version:{app.Version}")

                # Erstellen Sie die SQLAlchemy-Datenbankinstanz
                db = SQLAlchemy(app)



                # Definieren Sie das Baustellenmodell
                class Construction(db.Model):
                    id = db.Column(db.Integer, primary_key=True)
                    title = db.Column(db.String(100), nullable=False)
                    description = db.Column(db.Text, nullable=True)
                    address = db.Column(db.String(200), nullable=False)
                    start_date = db.Column(db.String(10), nullable=False)
                    end_date = db.Column(db.String(10), nullable=False)
                    latitude = db.Column(db.Float, nullable=True)
                    longitude = db.Column(db.Float, nullable=True)


                class UserRole(Enum):
                    ADMIN = "Admin"
                    EDITOR = "Editor"
                    VIEWER = "Viewer"


                class User(db.Model):
                    id = db.Column(db.Integer, primary_key=True)
                    username = db.Column(db.String(80), unique=True, nullable=False)
                    hashed_password = db.Column(db.String(128), nullable=False)
                    role = db.Column(db.Enum(UserRole), nullable=False,
                                     default=UserRole.VIEWER)  # Standardrolle ist Viewer


                def create_user(username, hashed_password, role):
                    # Erstellen Sie den Anwendungskontext
                    with app.app_context():
                        # Überprüfen, ob der Benutzer bereits existiert
                        existing_user = User.query.filter_by(username=username).first()
                        if existing_user:
                            logging.info(f"User '{username}' already exists.")
                        else:
                            # Hashen Sie das Passwort bevor Sie es in der Datenbank speichern
                            hashed_password = bcrypt.generate_password_hash(hashed_password).decode('utf-8')

                            # Erstellen Sie den neuen Benutzer mit der angegebenen Rolle
                            new_user = User(username=username, hashed_password=hashed_password, role=UserRole(role))
                            db.session.add(new_user)
                            db.session.commit()
                            logging.info(f"User '{username}' was created successfully with role '{role}'.")


                with app.app_context():
                    db.create_all()
                    create_user('poweruser', 'powerAdmin',UserRole.ADMIN.value)  # Der poweruser erhält die Rolle "Admin"


                @app.errorhandler(Exception)
                def log_exceptions(error):
                    app.logger.error('Error: %s', error)
                    logging.error(error)
                    return "Internal Server Error", 500


                @app.route('/create_user', methods=['POST'])
                def create_user():
                    if 'username' not in session:
                        return redirect(url_for('login'))
                    if request.method == 'POST':
                        username = request.form['username']
                        password = request.form['password']
                        role = request.form.get('role')  # Hole die ausgewählte Rolle aus dem Formular

                        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

                        # Erstelle einen neuen Benutzer mit der ausgewählten Rolle
                        new_user = User(username=username, hashed_password=hashed_password, role=UserRole(role))
                        db.session.add(new_user)
                        db.session.commit()
                        logging.info(f"A new user has been created - {username}")

                    return render_template('success.html', Message=f"Der User {username} wurde erfolgreich angelegt", Version=app.Version, City=City)


                @app.route('/delete_user/<int:user_id>', methods=['GET'])
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


                @app.route('/change_password/<int:user_id>', methods=['GET', 'POST'])
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

                    return render_template('change_password.html', user=user_to_change)


                @app.route('/change_role/<int:user_id>', methods=['GET', 'POST'])
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

                    return render_template('change_role.html', user=user_to_change)


                @app.route('/dbconfig')
                def dbconfig():
                    if 'username' not in session:
                        return redirect(url_for('login'))
                    error_message = "Fehler - Die Konfiguration von anderen Datenbanken folgt in einer späteren Version."
                    return render_template('error.html', error_message=error_message, Version=app.Version, City=City)

                @app.route(f'/login', methods=['GET', 'POST'])
                def login():
                    try:
                        if request.method == 'POST':
                            # Get the username and password entered in the HTML form
                            username = request.form.get('username')
                            password = request.form.get('password')


                            # Check if the user exists in the database
                            user = User.query.filter_by(username=username).first()
                            logging.info(user)

                            if user and bcrypt.check_password_hash(user.hashed_password, password):
                                # Set the authenticated user's ID in the session
                                session['username'] = username
                                return redirect(url_for('index'))

                            # If the username and password were not valid, show an error message
                            error_message = "Die eingegebenen Daten stimmen nicht überein."
                            return render_template('login.html', error_message=error_message)

                        return render_template('login.html', Version=app.Version, City=City)
                    except Exception as errorhandler:
                        logging.error(errorhandler)


                @app.route('/user-config')
                def users():
                    if 'username' not in session:
                        return redirect(url_for('login'))
                    users = User.query.all()
                    # Get the username from the session
                    username = session.get('username')
                    if username:
                        user = User.query.filter_by(username=username).first()
                        user_role = user.role

                    if user_role == UserRole.ADMIN:
                        # Get all users from the database
                        all_users = User.query.all()

                        # Filter out the "FleAdmin" user (optional, falls erforderlich)
                        filtered_users = [user for user in all_users if user.username != 'poweruser']

                        # Create a list of dictionaries containing user information
                        user_list = []
                        for user in filtered_users:
                            user_info = {'username': user.username}
                            user_list.append(user_info)

                        return render_template('usersmanagment.html', users=users, Version=app.Version, City=City)

                    # If the username is not "FleAdmin", show an error message
                    error_message = "Fehler - Es scheint so, als hättest du für diesen Bereich keine Berechtigung."
                    logging.error(f"The User {username} has no authorization.")
                    return render_template('error.html', error_message=error_message, Version=app.Version, City=City)

                @app.route('/')
                @cache.cached(timeout=60)
                def index():
                    if 'username' not in session:
                        return redirect(url_for(f'login'))
                    active_constructions = Construction.query.all()
                    username = session.get('username')
                    username = session.get('username')
                    if username:
                        user = User.query.filter_by(username=username).first()
                        user_role = user.role
                    return render_template('index.html', constructions=active_constructions, Version=app.Version, username=username, City=City, user_role=user_role)


                @app.route('/get_constructions', methods=['GET'])
                def get_constructions():
                    if 'username' not in session:
                        return redirect(url_for('login'))
                    constructions = Construction.query.all()
                    construction_list = []
                    for construction in constructions:
                        construction_info = {
                            'title': construction.title,
                            'address': construction.address,
                            'latitude': construction.latitude,
                            'longitude': construction.longitude
                        }
                        construction_list.append(construction_info)
                    return jsonify(construction_list)

                @app.route('/new_traffic_entry')
                @cache.cached(timeout=60)
                def new_traffic_entry():
                    if 'username' not in session:
                        return redirect(url_for('login'))
                    return render_template('new_traffic_entry.html', Version=app.Version)


                @app.route('/entry_revoke')
                @cache.cached(timeout=60)
                def entry_revoke():
                    if 'username' not in session:
                        return redirect(url_for('login'))
                    active_constructions = Construction.query.all()
                    return render_template('entry_revoke.html',constructions=active_constructions, Version=app.Version)


                @app.route('/rest/v1/route/alert', methods=['GET'])
                def alert_route():
                    if 'username' not in session:
                        return redirect(url_for('login'))
                    destination_coords = {
                        'data.latitude': 50.822942745215016,
                        'data.longitude': 6.13288970078409
                    }

                    return jsonify(destination_coords)


                @app.route('/rest/v1/external/maps', methods=['GET'])
                def interface_external():
                    if 'username' not in session:
                        return redirect(url_for('login'))

                    # Hier holen Sie sich die Construction-Einträge aus der Datenbank:
                    constructions = Construction.query.all()

                    # Jetzt erstellen Sie eine Liste von JSON-Einträgen:
                    construction_list = []
                    for construction in constructions:
                        construction_info = {
                            'title': construction.title,
                            'address': construction.address,
                            'latitude': construction.latitude,
                            'longitude': construction.longitude
                        }
                        construction_list.append(construction_info)

                    # Geben Sie die Liste als JSON zurück:
                    return jsonify(construction_list)


                @app.route('/rest/v1/alertservice/generate_key', methods=['POST'])
                def generate_access_key():
                    if 'username' not in session:
                        return redirect(url_for('login'))
                    username = session.get('username')
                    if username:
                        user = User.query.filter_by(username=username).first()
                        user_role = user.role

                    if user_role == UserRole.ADMIN or user_role == UserRole.EDITOR:
                        logging.info("A new ALERTKEY is generated")
                        # Generate a new Access Key (for example, 20 characters long alphanumeric)
                        new_key = ''.join(random.choices(string.ascii_letters + string.digits, k=20))


                        # Write the new environment variables to the .env file
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

                @app.route('/rest/v1/alertservice')
                @cache.cached(timeout=60)
                def alertservice():
                    if 'username' not in session:
                        return redirect(url_for('login'))
                    username = session.get('username')
                    if username:
                        user = User.query.filter_by(username=username).first()
                        user_role = user.role

                    if user_role == UserRole.ADMIN:
                        AlamosLink = f"[FQDN]:[PORT]/rest/v1/alertservice/alamos/{ALERTKEY}"
                        return render_template('alertservice.html', Version=app.Version, City=City, ALERTKEY=ALERTKEY,
                                               AlamosLink=AlamosLink)

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


                @app.route(f'/rest/v1/alertservice/alamos/{ALERTKEY}', methods=['POST', 'GET'])
                def alamos_webhook():
                    if request.method == 'POST':
                        # Verarbeite POST-Anfragen
                        logging.info("Receive new ALERT - POST")
                        data = request.get_json()
                        unit = data.get('unit')
                        keyword = data.get('keyword')
                        if unit and keyword:
                            save_to_json_file(unit, keyword)
                            return jsonify({'message': 'POST-Anfrage erfolgreich verarbeitet'})

                    elif request.method == 'GET':
                        # Verarbeite GET-Anfragen
                        logging.info("Receive new ALERT - GET")
                        unit = request.args.get('unit')
                        keyword = request.args.get('keyword')
                        if unit and keyword:
                            save_to_json_file(unit, keyword)
                            return jsonify({'message': 'GET-Anfrage erfolgreich verarbeitet'})

                    return jsonify({'message': 'NOT_OK'}), 405

                @app.route('/delete_construction/<int:construction_id>', methods=['GET', 'POST'])
                def delete_construction(construction_id):
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
                    # If the username is not ..., show an error message
                    error_message = "Fehler - Es scheint so, als hättest du für diesen Vorgang keine Berechtigung."
                    logging.error(f"The User {username} has no authorization.")
                    return render_template('error.html', error_message=error_message)

                @app.route('/add_construction', methods=['POST'])
                def add_construction():
                    if 'username' not in session:
                        return redirect(url_for('login'))
                    username = session.get('username')
                    if username:
                        user = User.query.filter_by(username=username).first()
                        user_role = user.role

                    if user_role == UserRole.ADMIN or user_role == UserRole.EDITOR:
                        title = request.form['title']
                        description = request.form['description']
                        address = request.form['address']
                        start_date = request.form['start_date']
                        end_date = request.form['end_date']
                        latitude = request.form['latitude']
                        longitude = request.form['longitude']
                        new_construction = Construction(title=title, description=description, address=address,
                                                        start_date=start_date, end_date=end_date, latitude=latitude, longitude=longitude)
                        db.session.add(new_construction)
                        db.session.commit()
                        logging.info(f"New traffic situation entered {new_construction}")

                        active_constructions = Construction.query.all()
                        return redirect(url_for('index'))
                    # If the username is not ..., show an error message
                    error_message = "Fehler - Es scheint so, als hättest du für diesen Vorgang keine Berechtigung."
                    logging.error(f"The User {username} has no authorization.")
                    return render_template('error.html', error_message=error_message)


                @app.route('/system')
                @cache.cached(timeout=60)
                def systemweb():
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
                       total_space = disk_usage.total / (1024 ** 3)  # Convert to gigabytes
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
        #logger.error(errorhandler)
