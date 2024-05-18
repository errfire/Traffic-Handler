#!/usr/bin/env python3
#ERR-FIRE
#Billel Meftah


from flask import Flask, render_template, redirect, url_for, request, session,jsonify
from config_loader import City
from flask_bcrypt import Bcrypt
from app import app, cache, oauth_enabled, oauth_disabled, NoAuth
from flask import Blueprint
from utils import get_user_and_constructions, UserRole, User
import os
import json

ALERTKEY = os.getenv("ALERTKEY")
app.logger.info("Load Modul Alertservice")

conf_dir = os.path.join("..", "..", "conf")
conf_file_path = os.path.join(conf_dir, "settings.cfg")

alert_bp = Blueprint('Alertservice', __name__)
bcrypt = Bcrypt(app)


DATA_DIRECTORY = os.path.join("..", "..", "data")

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

        error_message = NoAuth
        app.logger.error(f"The User {username} wir role {user_role} has no authorization.")
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

        error_message = NoAuth
        app.logger.error(f"The User {username} wir role {user_role} has no authorization.")
        return render_template('error.html', error_message=error_message, Version=app.Version, City=City)

def save_to_json_file(unit, keyword):
    data = {
        "unit": unit,
        "keyword": keyword
    }
    filename = os.path.join(DATA_DIRECTORY, "alert.json")
    try:
        with open(filename, "w") as json_file:
            json.dump(data, json_file)
    except Exception as e:
        app.logger.error(f"Failed to save to json file - {str(e)}")
        return "Failed to save to json file", 500
    return filename


@app.route(f'/rest/v1/alertservice/{ALERTKEY}', methods=['POST', 'GET'])
def alertserv():
    if request.method == 'POST':
        app.logger.info("Receive new ALERT - POST")
        data = request.get_json()
        unit = data.get('unit')
        keyword = data.get('keyword')
        app.logger.debug(f"Receive new ALERT - POST-Request with following Parameter {unit} and {keyword}")
        if unit and keyword:
            save_to_json_file(unit, keyword)
            return jsonify({'message': 'POST-Anfrage erfolgreich verarbeitet'})

    elif request.method == 'GET':
        app.logger.info("Receive new ALERT - GET")
        unit = request.args.get('unit')
        keyword = request.args.get('keyword')
        app.logger.debug(f"Receive new ALERT - GET-Request with following Parameter {unit} and {keyword}")
        if unit and keyword:
            save_to_json_file(unit, keyword)
            return jsonify({'message': 'GET-Anfrage erfolgreich verarbeitet'})

    return jsonify({'message': 'NOT_OK'}), 405