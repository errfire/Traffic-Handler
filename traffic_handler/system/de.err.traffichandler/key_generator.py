#!/usr/bin/env python3
#ERR-FIRE
#Billel Meftah

import string
import random


def generate_alert_key(length=32):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))

def generate_secret_key(length=32):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(length))

def create_env_file(secret_key, alert_key):
    with open('.env', 'w') as env_file:
        env_file.write(f"SECRET_KEY={secret_key}\nALERTKEY={alert_key}")

