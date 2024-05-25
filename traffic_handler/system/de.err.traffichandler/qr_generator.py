#!/usr/bin/env python3
#ERR-FIRE
#Billel Meftah

from app import app


import qrcode

app.logger.info("Load Modul QRCODE")
def generate_qr_code(latitude, longitude, description, filename):
    google_maps_url = f"https://www.google.com/maps?q={latitude},{longitude}({description})"

    # Erstellen Sie den QR-Code
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(google_maps_url)
    qr.make(fit=True)

    # Speichern Sie den QR-Code als Bild
    img = qr.make_image(fill='black', back_color='white')
    img.save(filename)