#!/usr/bin/env python3
#ERR-FIRE
#Billel Meftah

import sys
import platform
import re
import psutil

import json
import base64
import csv
import os
import smtplib

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
from flask import render_template, request, redirect, url_for, session, jsonify, flash, send_file, send_from_directory
from utils import create_user, get_user_and_constructions
from app import app, db, bcrypt, oauth_enabled, oauth_disabled, cache, ALLOWED_EXTENSIONS, UPLOAD_FOLDER, NoAuth
from models import Drawing, User, UserRole, OAuthUser, Construction, SmtpConfig, Secure
from models import Imagelogo
from email.mime.base import MIMEBase
from email import encoders
from pdf_generator import generate_pdf
from health import health_bp
from usermanagment import user_bp
from alertservice import alert_bp
from config_loader import port, host,City, ssl_settings

conf_dir = os.path.join("..", "..", "conf")
key = Fernet.generate_key()
cipher_suite = Fernet(key)

conf_dir = os.path.join("..", "..", "conf")
conf_file_path = os.path.join(conf_dir, "settings.cfg")


with app.app_context():
    db.create_all()
    create_user('poweruser', 'powerAdmin', UserRole.ADMIN.value)




    ###########################
    ######## Endpoints ########
    ###########################

    if oauth_enabled:
        from iam import iam_bp
        app.register_blueprint(iam_bp)
    else:
        None

    app.register_blueprint(health_bp)
    app.register_blueprint(user_bp)
    app.register_blueprint(alert_bp)

    @app.route('/generate_pdf/<int:construction_id>')
    def generate_pdf_route(construction_id):
        if oauth_enabled:
            username, user_role, active_constructions = get_user_and_constructions()

            if username is None or user_role != UserRole.ADMIN:
                error_message = NoAuth
                return render_template('error.html', error_message=error_message, Version=app.Version,
                                       City=City)
        elif oauth_disabled:
            if 'username' not in session:
                return redirect(url_for(f'login'))

            active_constructions = Construction.query.all()
            username = session.get('username')
            if username:
                user = User.query.filter_by(username=username).first()

                return generate_pdf(construction_id, Construction, app)


    def allowed_file(filename):
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


    @app.route('/rest/v1/emailfile', methods=['POST'])
    def upload_csv_email_file():
        try:

            if oauth_enabled:
                username, user_role, active_constructions = get_user_and_constructions()

                if username is None or user_role != UserRole.ADMIN:
                    error_message = NoAuth
                    return render_template('error.html', error_message=error_message, Version=app.Version,
                                           City=City)

            elif oauth_disabled:
                if 'username' not in session:
                    return redirect(url_for('login'))
                username = session.get('username')
                user = User.query.filter_by(username=username).first()
                if not user or user.role != UserRole.ADMIN:
                    error_message = NoAuth
                    return render_template('error.html', error_message=error_message, Version=app.Version,
                                           City=City)

            if 'file' not in request.files:
                flash('Keine Datei ausgewählt!', 'error')
                return redirect(request.url)

            file = request.files['file']

            if file.filename != 'err_mailreceiver.csv':
                app.logger.error("Try to uploade file with wrong name!")
                error_message = "Der Dateiname entspricht nicht der Richtlinie!"
                return render_template('error.html', error_message=error_message, Version=app.Version, City=City)

            if file.filename == '':
                app.logger.error("No file has been selected for upload")
                error_message = "Es wurde keine Datei ausgewählt zum hochladen!"
                return render_template('error.html', error_message=error_message, Version=app.Version, City=City)

            if file.filename == 'err_mailreceiver.csv':
                filename = secure_filename(file.filename)
                file.save(os.path.join(UPLOAD_FOLDER, filename))
                app.logger.info("New CSV uploade for Mailing")
                flash('Die Datei wurden erfolgreich gespeichert!', 'success')
                return render_template('emailupload.html', Version=app.Version, City=City)

        except Exception as e:
            app.logger.error(str(e))
            return render_template('error.html', error_message=str(e), Version=app.Version, City=City)

        return render_template('error.html', error_message="Ein unbekannter Fehler ist aufgetreten.",
                               Version=app.Version, City=City)

    def get_uploaded_files():
        files = []
        for filename in os.listdir(UPLOAD_FOLDER):
            file_path = os.path.join(UPLOAD_FOLDER, filename)
            timestamp = os.path.getmtime(file_path)
            timestamp = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
            files.append({'name': filename, 'timestamp': timestamp})
        return files

    @app.route('/emailupload')
    def receiver():
        if oauth_enabled:
            username, user_role, active_constructions = get_user_and_constructions()

            if username is None or user_role != UserRole.ADMIN:
                error_message = NoAuth
                return render_template('error.html', error_message=error_message, Version=app.Version, City=City)

        elif oauth_disabled:
            if 'username' not in session:
                return redirect(url_for('login'))
            username = session.get('username')
            user = User.query.filter_by(username=username).first()
            if not user or user.role != UserRole.ADMIN:
                error_message = NoAuth
                return render_template('error.html', error_message=error_message, Version=app.Version, City=City)

        files = get_uploaded_files()

        return render_template('emailupload.html', Version=app.Version, City=City, files=files)


    @app.route('/rest/v1/delete_drawing/<int:drawing_id>', methods=['DELETE'])
    def delete_drawing(drawing_id):
        try:
            if oauth_enabled:
                username, user_role, active_constructions = get_user_and_constructions()

                if username is None:
                    return redirect(url_for('login'))
                if user_role == UserRole.EDITOR:
                    drawing = Drawing.query.get(drawing_id)
                    if drawing:
                        db.session.delete(drawing)
                        db.session.commit()
                        return jsonify({'message': 'Zeichnung erfolgreich gelöscht'}), 200
                    else:
                        return jsonify({'error': 'Zeichnung nicht gefunden'}), 404
        except Exception as e:
            app.logger.error(e)
            return jsonify({'error': str(e)}), 500


    @app.route('/rest/v1/save_drawing', methods=['POST'])
    def save_drawing():
        try:
            if oauth_enabled:
                username, user_role, active_constructions = get_user_and_constructions()
                if not username:
                    return redirect(url_for('login'))
                if user_role not in [UserRole.ADMIN, UserRole.EDITOR]:
                    return jsonify({'error': 'Unauthorized access'}), 401
            elif oauth_disabled:
                if 'username' not in session:
                    return redirect(url_for('login'))
                username = session.get('username')
                user = User.query.filter_by(username=username).first()
                if not user:
                    return jsonify({'error': 'User not found'}), 404
                user_role = user.role
                if user_role not in [UserRole.ADMIN, UserRole.EDITOR]:
                    return jsonify({'error': 'Unauthorized access'}), 401
            app.logger.info("Receive new map-drawing")
            drawing_data = request.get_json()
            new_drawing = Drawing(geometry=json.dumps(drawing_data['geometry']))
            app.logger.info("Statr writing in Database.")
            db.session.add(new_drawing)
            db.session.commit()

            return jsonify({'message': 'Zeichnung erfolgreich gespeichert'}), 201
        except Exception as e:
            app.logger.error(e)
            return jsonify({'error': str(e)}), 500


    @app.route('/rest/v1/get_drawings', methods=['GET'])
    def get_drawings():
        try:
            if oauth_enabled:
                username, user_role, active_constructions = get_user_and_constructions()

                if username is None:
                    return redirect(url_for('login'))

            elif oauth_disabled:
                if 'username' not in session:
                    return redirect(url_for('login'))
            drawings = Drawing.query.all()
            drawings_data = [{'geometry': json.loads(d.geometry)} for d in drawings]
            return jsonify(drawings_data)
        except Exception as e:
            return jsonify({'error': str(e)}), 500


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

            if username is None or user_role != UserRole.ADMIN:
                error_message = NoAuth
                return render_template('error.html', error_message=error_message, Version=app.Version, City=City)

        elif oauth_disabled:
            if 'username' not in session:
                return redirect(url_for('login'))

            username = session.get('username')
            user = User.query.filter_by(username=username).first()
            if not user or user.role != UserRole.ADMIN:
                error_message = NoAuth
                return render_template('error.html', error_message=error_message, Version=app.Version, City=City)

        all_users = User.query.all()
        filtered_users = [user for user in all_users if user.username != 'poweruser']

        smtp_config = SmtpConfig.query.first()
        if smtp_config is not None:
            smtp_server = smtp_config.smtp_server
            smtp_port = smtp_config.smtp_port
            smtp_username = smtp_config.smtp_username
            smtp_secure = smtp_config.smtp_secure
        else:
            # Fallback values
            smtp_server = "default_smtp_server"
            smtp_port = 587
            smtp_username = "default_username"
            smtp_secure = Secure.FALSE

        image = Imagelogo.query.first()
        image_data = image.image_data if image else None
        image_base64 = base64.b64encode(image_data).decode('utf-8') if image_data else None

        return render_template('settings.html', Version=app.Version, City=City, smtp_server=smtp_server,smtp_port=smtp_port,smtp_username=smtp_username,smtp_secure=smtp_secure, image=image_base64)

    UPLOAD_ALLOWED_EXTENSIONS = {'png'}

    def uploadallowed(filename):
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in UPLOAD_ALLOWED_EXTENSIONS

    @app.route('/upload_image', methods=['POST'])
    def upload_image():
        if 'image' in request.files:
            image = request.files['image']
            if image.filename != '' and uploadallowed(image.filename):
                filename = secure_filename(image.filename)
                image_data = image.read()
                existing_image = Imagelogo.query.first()
                if existing_image:
                    existing_image.image_data = image_data
                else:
                    new_image = Imagelogo(image_data=image_data)
                    db.session.add(new_image)
                db.session.commit()
                app.logger.info('New logo successfully uploaded!')
                return redirect(url_for('settings'))
        upload_error = 'Kein Logo ausgewählt oder Fehler beim Hochladen.'
        app.logger.error(upload_error)
        return render_template('error.html', error_message=upload_error, Version=app.Version, City=City)


    @app.route('/ereignisprotokoll')
    def events():
        if oauth_enabled:
            username, user_role, active_constructions = get_user_and_constructions()

            if not username or user_role != UserRole.ADMIN:
                return render_template('error.html', error_message=NoAuth, Version=app.Version, City=City)


        elif oauth_disabled:
            if 'username' not in session:
                return redirect(url_for('login'))
            username = session.get('username')
            user = User.query.filter_by(username=username).first()
            if not user or user.role != UserRole.ADMIN:
                error_message = NoAuth
                return render_template('error.html', error_message=error_message, Version=app.Version, City=City)

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


    @app.route('/save_smtp_settings', methods=['POST', 'GET'])
    def save_smtp_settings():
        try:
            username, user_role = get_user_and_role()

            if username and user_role == UserRole.ADMIN:
                smtp_server = request.form.get('smtp-server')
                smtp_port = request.form.get('smtp-port')
                smtp_username = request.form.get('smtp-username')
                smtp_password = request.form.get('smtp-password')
                encrypted_password = cipher_suite.encrypt(smtp_password.encode())
                encoded_password = base64.b64encode(encrypted_password).decode()
                SmtpConfig.query.delete()

                new_config = SmtpConfig(smtp_server=smtp_server, smtp_port=smtp_port, smtp_username=smtp_username,
                                        smtp_password=encoded_password, smtp_secure=Secure.TRUE)
                db.session.add(new_config)
                db.session.commit()
                flash('SMTP-Einstellungen wurden erfolgreich gespeichert!', 'success')
                return render_template('settings.html')
            else:
                return redirect(url_for('login'))
        except:
            return redirect(url_for('login'))

    def get_user_and_role():
        if oauth_enabled:
            username, user_role, _ = get_user_and_constructions()
        elif oauth_disabled and 'username' in session:
            username = session.get('username')
            user = User.query.filter_by(username=username).first()
            user_role = user.role if user else None
        else:
            username = user_role = None
        return username, user_role

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
                error_message = NoAuth
                app.logger.error(f"The User {username} has no authorization.")
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

            error_message = NoAuth
            app.logger.error(f"The User {username} has no authorization.")
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
                    'type': construction.type,
                    'length': construction.length,
                    'width': construction.width,
                    'height': construction.height,
                    'weight': construction.weight
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
                    'type': construction.type,
                    'length': construction.length,
                    'width': construction.width,
                    'height': construction.height,
                    'weight': construction.weight
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

    @app.route('/rest/v1/debug-sate')
    @cache.cached(timeout=60)
    def debug_sate():
        if oauth_enabled:
            username, user_role, active_constructions = get_user_and_constructions()

            if username is None:
                return redirect(url_for('login'))
            return jsonify(debug=app.debug)

        elif oauth_disabled:
            if 'username' not in session:
                return redirect(url_for('login'))
            return jsonify(debug=app.debug)

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
            return render_template('entry_revoke.html', constructions=active_constructions, Version=app.Version)

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
    @app.route('/profile', methods=['GET', 'POST'])
    def profile():
        if oauth_enabled:

            return render_template('error.html', error_message="Benutzername und Passwort nur über das IAM veränderbar. Bitte kontaktieren Sie Ihren Administrator.", Version=app.Version,
                                   City=City)
        elif oauth_disabled:
            if 'username' not in session:
                return redirect(url_for(f'login'))

        username = session.get('username')
        if username:
            user = User.query.filter_by(username=username).first()
            user_role = user.role

        user = User.query.filter_by(username=session['username']).first()
        if not user:
            return render_template('error.html', error_message="Benutzer nicht gefunden!", Version=app.Version,
                                   City=City)

        if request.method == 'POST':
            new_password = request.form['password']

            if new_password:
                user.hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')

            db.session.commit()
            flash('Profil erfolgreich aktualisiert.', 'success')
            return redirect(url_for('profile'))

        return render_template('profile.html', Version=app.Version, user=user, username=username, City=City, user_role=user_role)


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
                app.logger.info(f"The following entry was deleted {construction_id}")
                return redirect(url_for('entry_revoke'))
            error_message = NoAuth
            app.logger.error(f"The User {username} has no authorization.")
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
                app.logger.info(f"The following entry was deleted {construction_id}")
                return redirect(url_for('entry_revoke'))
            error_message = NoAuth
            app.logger.error(f"The User {username} has no authorization.")
            return render_template('error.html', error_message=error_message)


    @app.route('/rest/v1/add_construction', methods=['POST'])
    def add_construction():
        try:
            if oauth_enabled:
                username, user_role, active_constructions = get_user_and_constructions()

                if not username or user_role != UserRole.ADMIN:
                    return render_template('error.html', error_message=NoAuth, Version=app.Version, City=City)


            elif oauth_disabled:
                if 'username' not in session:
                    return redirect(url_for('login'))
                username = session.get('username')
                user = User.query.filter_by(username=username).first()
                if not user or user.role != UserRole.ADMIN:
                    error_message = NoAuth
                    return render_template('error.html', error_message=error_message, Version=app.Version, City=City)

            app.logger.info("Start process add new construction entry!")
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
            length = request.form['length']
            width = request.form['width']
            height = request.form['height']
            weight = request.form['weight']
            send_email = request.form.get('send_email')
            app.logger.info("Check if Attachment is attach...")
            if 'attachment' in request.files:
                attachment = request.files['attachment']
                if attachment:
                    app.logger.info("User uploaded Attachment. Start handling.")
                    attachment_filename = secure_filename(attachment.filename)
                    dir_path = "../../includes/construction"
                    if not os.path.exists(dir_path):
                        try:
                            os.makedirs(dir_path)
                            app.logger.info(f"The path {dir_path} was created successful.")
                        except PermissionError:
                            app.logger.error( f"No Permission to create the following Path {dir_path}. Pleas check the Permission.")
                    else:
                        app.logger.debug(f"The path {dir_path} already exists.")
                    attachment.save(os.path.join(dir_path, attachment_filename))
                    app.logger.info("Attachment saved.")
                    part = MIMEBase('application', "octet-stream")
                    with open(os.path.join(dir_path, attachment_filename), 'rb') as file:
                        part.set_payload(file.read())
                    encoders.encode_base64(part)
                    part.add_header('Content-Disposition', 'attachment', filename=attachment_filename)

                    message = MIMEMultipart()

            else:
                app.logger.info("No  Attachment is attach!")
            new_construction = Construction(title=title, description=description, strasse=strasse, plz=plz, ort=ort,
                                            start_date=start_date, end_date=end_date, latitude=latitude,
                                            longitude=longitude, type=type, length=length, width=width, height=height,
                                            weight=weight)
            db.session.add(new_construction)
            db.session.commit()

            app.logger.info(f"New traffic situation entered {new_construction}")

            if send_email:
                smtp_config = SmtpConfig.query.first()
                app.logger.info("Start sending EMail with new traffic situation")
                smtp_server = smtp_config.smtp_server
                smtp_port = int(smtp_config.smtp_port)
                smtp_username = smtp_config.smtp_username
                smtp_password = cipher_suite.decrypt(base64.b64decode(smtp_config.smtp_password.encode())).decode()
                smtp_secure = smtp_config.smtp_secure == Secure.TRUE

                app.logger.info("Start pars E-Mail Address from CSV File")
                csv_file_path = os.path.join(UPLOAD_FOLDER, 'err_mailreceiver.csv')
                recipients = []
                with open(csv_file_path, newline='') as csvfile:
                    reader = csv.DictReader(csvfile)
                    for row in reader:
                        recipients.append(row['email'])
                app.logger.info("Start Build the E-Mail.")
                message = MIMEMultipart()
                message['From'] = smtp_username
                message['To'] = ", ".join(recipients)
                message['Subject'] = f"TrafficHandler: Neue Verkehrshindernis hinzugefügt! {title} {new_construction}"
                body = (f"Hallo,\n\n Es wurde von {username} folgender Eintrag, mit der Bitte um Beachtung angelegt.\n\nTitel: {title}\nBeschreibung: {description}\nStraße: {strasse}\nPLZ: {plz}\nOrt: {ort}\nStartdatum: {start_date}\nEnddatum: {end_date}\nBreitengrad: {latitude}\nLängengrad: {longitude}\nTyp: {type}\n\n\nBitte beachten Sie folgende Hinweise für Fahrzeuge.\n\nLänge: {length}\nBreite: {width}\nHöhe: {height}\nGewicht: {weight}\n\n"
                        f"Freundliche Grüße\n {username}")
                message.attach(MIMEText(body, 'plain'))
                message.attach(part)

                with smtplib.SMTP(smtp_server, smtp_port) as server:
                    if smtp_secure:
                        server.starttls()
                        app.logger.debug("Sending EMail with TLS - Secure.")
                    server.login(smtp_username, smtp_password)
                    server.sendmail(smtp_username, recipients, message.as_string())
                    app.logger.info(f"Sending EMail to: {recipients}")

            active_constructions = Construction.query.all()
            return redirect(url_for('index'))

        except Exception as e:
            db.session.rollback()
            app.logger.error(e)
            return "Failed to add construction", 500

    @app.route('/endpoints', methods=['GET'])
    def list_endpoints():
        if oauth_enabled:
            username, user_role, active_constructions = get_user_and_constructions()

            if not username or user_role != UserRole.ADMIN:
                return redirect(url_for('login'))

        elif oauth_disabled:
            if 'username' not in session or User.query.filter_by(
                    username=session.get('username')).first().role != UserRole.ADMIN:
                return jsonify({'message': 'No authorization'}), 401

        routes = [{'url': rule.rule, 'endpoint': rule.endpoint} for rule in app.url_map.iter_rules() if
                  'static' not in rule.endpoint]

        endpoints = {route['endpoint']: request.url_root + route['url'] for route in routes}

        return jsonify(endpoints=endpoints)

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

            error_message = NoAuth
            app.logger.error(f"The User {username} has no authorization.")
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

            error_message = NoAuth
            app.logger.error(f"The User {username} has no authorization.")
            return render_template('error.html', error_message=error_message)

    if __name__ == '__main__':
        app.run(ssl_context=ssl_settings, host=host, port=port)
