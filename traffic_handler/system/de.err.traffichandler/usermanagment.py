#!/usr/bin/env python3
#ERR-FIRE
#Billel Meftah


from config_loader import usessl, port, host, cert, key, URL, City, login_basic, ssl_settings
from flask import render_template, redirect, url_for, request, session, flash
from flask_bcrypt import Bcrypt
from models import User, UserRole
from app import app, db, bcrypt, oauth_enabled, oauth_disabled
from flask import Blueprint
from urllib.parse import quote_plus, urlencode
import os

import configparser

app.logger.info("Load Modul Usermanagement")

conf_dir = os.path.join("..", "..", "conf")
conf_file_path = os.path.join(conf_dir, "settings.cfg")

user_bp = Blueprint('mismanagement', __name__)
bcrypt = Bcrypt(app)

config = configparser.ConfigParser()
config.read('../../conf/iam.ini')
Authservice= config.get('IAM', 'Auth-Service')
ClientID=config.get('IAM', 'IAM_CLIENT_ID')
IAMDomain=config.get("IAM", "IAM_DOMAIN")
@app.route('/rest/v1/loginbasic/create_user', methods=['POST'])
def create_user():
    if 'username' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        role = request.form.get('role')

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        new_user = User(username=username, hashed_password=hashed_password, role=UserRole(role), email=email)
        db.session.add(new_user)
        db.session.commit()
        app.logger.info(f"A new user has been created - {username}")

    return render_template('success.html', Message=f"Der User {username} wurde erfolgreich angelegt", Version=app.Version, City=City)


@app.route('/rest/v1/loginbasic/delete_user/<int:user_id>', methods=['GET'])
def delete_user(user_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    user_to_delete = User.query.get_or_404(user_id)

    if user_to_delete.username == 'poweruser':
        error_message = f"Fehler - Der User {user_to_delete.username} darf nicht gelöscht werden."
        app.logger.error(error_message)
        return render_template('error.html', error_message=error_message, Version=app.Version,
                               City=City)

    db.session.delete(user_to_delete)
    db.session.commit()
    app.logger.info(f"The following user was deleted - {user_to_delete.username}")

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

@app.route('/rest/v1/loginbasic/change_email/<int:user_id>', methods=['GET', 'POST'])
def change_email(user_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    user_to_change = User.query.get_or_404(user_id)

    if request.method == 'POST':
        new_email = request.form['new_email']

        if User.query.filter_by(email=new_email).first():
            app.logger.error(f"User {user_id} changed E-Mail but E-Mail already in use! {new_email}!!!")
            return render_template('error.html', error_message="Die E-Mail-Adresse wird bereits verwendet", Version=app.Version, City=City)
        user_to_change.email = new_email
        db.session.commit()
        app.logger.info(f"User {user_id} changed E-Mail! {new_email}!!!")
        return render_template('success.html', Message="Die E-Mail wurde erfolgreich geändert", Version=app.Version, City=City)

    return render_template('change_email.html', user=user_to_change, Version=app.Version, City=City)

@app.route('/rest/v1/loginbasic/change_role/<int:user_id>', methods=['GET', 'POST'])
def change_role(user_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    user_to_change = User.query.get_or_404(user_id)

    if request.method == 'POST':
        new_role = request.form['new_role']
        if new_role in ['VIEWER', 'EDITOR', 'ADMIN']:
            user_to_change.role = new_role
            app.logger.debug(f"Change Role from User {user_to_change}: {new_role}")
            db.session.commit()
            return render_template('success.html', Message="Die Rolle wurde erfolgreich geändert",
                                   Version=app.Version, City=City)

    return render_template('change_role.html', user=user_to_change ,Version=app.Version, City=City)


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
                app.logger.error(f"Incorrect login detected. Following user: {username}")
                return render_template('login.html', error_message=error_message, Version=app.Version,
                                       City=City)

            return render_template('login.html', Version=app.Version, City=City)
        elif oauth_enabled:
                return redirect('/rest/v1/auth/oauth/login')
    except Exception as errorhandler:
        app.logger.error(errorhandler)


@app.route('/logout', methods=['GET', 'POST'])
def logout():
    if oauth_enabled:
        app.logger.debug(f"User logout")
        session.clear()
        return redirect(
            "https://" + IAMDomain
            + "/v2/logout?"
            + urlencode(
                {
                    "returnTo": url_for("login", _external=True),
                    "client_id": ClientID,
                },
                quote_via=quote_plus,
            )
        )
    if 'username' in session:
        app.logger.debug(f"User logout")
        session.pop('username', None)
        flash('Erfolgreich abgemeldet!', 'success')
    else:
        flash("NOT OK", 'danger')
    return redirect(url_for('login'))