#!/usr/bin/env python3
#ERR-FIRE
#Billel Meftah


from flask import session
from models import Construction, OAuthUser, UserRole, User
from app import db, app, bcrypt


def get_user_and_constructions():
    if 'user' not in session:
        return None, None, None  # Benutzer ist nicht angemeldet

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
    # Erstellen Sie den Anwendungskontext
    with app.app_context():
        # Überprüfen, ob der Benutzer bereits existiert
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            app.logger.debug(f"User '{username}' already exists.")
        else:
            # Hashen Sie das Passwort bevor Sie es in der Datenbank speichern
            hashed_password = bcrypt.generate_password_hash(hashed_password).decode('utf-8')

            # Erstellen Sie den neuen Benutzer mit der angegebenen Rolle
            new_user = User(username=username, hashed_password=hashed_password, role=UserRole(role))
            db.session.add(new_user)
            db.session.commit()
            app.logger.info(f"User '{username}' was created successfully with role '{role}'.")
