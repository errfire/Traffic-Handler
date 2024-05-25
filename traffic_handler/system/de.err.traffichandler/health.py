#!/usr/bin/env python3
#ERR-FIRE
#Billel Meftah

from flask import Blueprint
from app import app


app.logger.info("Load Modul Healthcheck")
health_bp = Blueprint('health', __name__)

@app.route('/rest/health', methods=['GET'])
def health_check():
    return "OK", 200
