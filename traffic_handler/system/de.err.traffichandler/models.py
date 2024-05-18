#!/usr/bin/env python3
#ERR-FIRE
#Billel Meftah

from enum import Enum
from flask_sqlalchemy import SQLAlchemy
from app import db

class UserRole(Enum):
    ADMIN = "Admin"
    EDITOR = "Editor"
    VIEWER = "Viewer"

class Secure(Enum):
    TRUE = "True"
    FALSE = "False"
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
    length = db.Column(db.String(10), nullable=True)
    width = db.Column(db.String(10), nullable=True)
    height = db.Column(db.String(10), nullable=True)
    weight = db.Column(db.String(10), nullable=True)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    hashed_password = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(85), nullable=False, default="example@err-fire.local")
    role = db.Column(db.Enum(UserRole), nullable=False,
                     default=UserRole.VIEWER)  # Standardrolle ist Viewer

class OAuthUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(100), nullable=True)
    emailverified = db.Column(db.Boolean, nullable=True, default=False)
    accesstoken = db.Column(db.String(256), nullable=False)
    role = db.Column(db.Enum(UserRole), nullable=False, default=UserRole.VIEWER)

class Drawing(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    geometry = db.Column(db.String, nullable=False)

class Imagelogo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    image_data = db.Column(db.LargeBinary, nullable=False)

class SmtpConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    smtp_server = db.Column(db.String(80), unique=True, nullable=False)
    smtp_port = db.Column(db.Integer, nullable=False)
    smtp_username = db.Column(db.String(100), nullable=True)
    smtp_password = db.Column(db.String(256), nullable=False)
    smtp_secure = db.Column(db.Enum(Secure), nullable=False, default=Secure.TRUE)
