#!/usr/bin/env python3
#ERR-FIRE
#Billel Meftah

import os

import io
from dotenv import load_dotenv
import libconf
from app import app
import sys

conf_dir = os.path.join("..", "..", "conf")
conf_file_path = os.path.join(conf_dir, "settings.cfg")
usessl = port = host = cert = key = URL = City = login_basic = ssl_settings = None

def load_general_config(conf_file_path):
    global usessl, port, host, cert, key, URL, City, login_basic, ssl_settings
    app.logger.info("Settings Configuration files have been initialized.")

    with io.open(conf_file_path, encoding='utf-8') as f:
        try:
            load_dotenv()
            cfg = libconf.load(f)
            limiter = cfg.get('limiter')
            usessl = cfg.get('useSSL')
            port = cfg.get('port')
            host = cfg.get('host')
            cert = cfg.get('cert')
            key = cfg.get('key')
            URL = cfg.get('url')
            City = cfg.get('city')
            share_location = cfg.get("SHAREDLOCATION")
            login_basic = cfg.get('LOGINBASIC')

            if share_location == "True":
                app.logger.info("Sahredlocation is active")
                app.logger.info("Start Communication with Backend-System")
            else:
                app.logger.info("Sahredlocation is deactivate")

            if usessl == "True":
                app.logger.info("SSL is enabled, start secure Connection")
                ssl_settings = (cert, key)
            elif usessl == "False":
                app.logger.info("No SSL connection. Start unsecure.")
                ssl_settings = None
            else:
                app.logger.error("No valid value in usessl. Application is terminated.")
                sys.exit(0)
        except Exception as e:
            app.logger.error(f"Error loading the general configuration: {e}")
    return usessl, port, host, cert, key, URL, City, login_basic, ssl_settings