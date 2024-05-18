#!/usr/bin/env python3
#ERR-FIRE
#Billel Meftah

from config_loader import load_general_config
from flask import render_template, redirect, url_for, request, session
from flask_bcrypt import Bcrypt
from models import OAuthUser, User
from app import app, db, bcrypt, oauth_enabled, oauth_disabled, oauth, Authservice
from flask import Blueprint
import os
from config_loader import usessl, port, host, cert, key, URL, City, login_basic, ssl_settings

app.logger.info("Load Modul IAM")

conf_dir = os.path.join("..", "..", "conf")
conf_file_path = os.path.join(conf_dir, "settings.cfg")

iam_bp = Blueprint('auth', __name__)
bcrypt = Bcrypt(app)

@app.route('/rest/v1/auth/oauth', methods=['GET', 'POST'])
def oauthadress():
    try:
        if oauth_enabled:
            return oauth.auth0.authorize_redirect(
                redirect_uri=url_for("oauth_callback", _external=True))
        elif oauth_disabled:
            error_message = "Fehlerhafter Anmeldeversuch."
            return render_template('login.html', error_message=error_message, Version=app.Version,
                                   City=City)
    except Exception as errorhandler:
        app.logger.error(errorhandler)


@app.route('/rest/v1/auth/oauth/login')
def oauth_login():
    if oauth_enabled:
        return render_template('oauth.html', authservice=Authservice,Version=app.Version,
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
                        app.logger.info("Login via OAuth user is created in database")
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
        app.logger.error(errorhandler)


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
                        app.logger.info("Login via Fallback")
                        return render_template('usersmanagment.html', Version=app.Version, City=City)

                    error_message = "Die eingegebenen Daten stimmen nicht überein."
                    app.logger.error(f"Incorrect login detected. Following user: {username}")
                    return render_template('login.html', error_message=error_message, Version=app.Version, City=City)

                return render_template('login.html', Version=app.Version, City=City)

    except Exception as errorhandler:
        app.logger.error(errorhandler)