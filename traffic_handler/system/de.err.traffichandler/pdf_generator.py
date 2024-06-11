#!/usr/bin/env python3
#ERR-FIRE
#Billel Meftah

import os
from datetime import date
from flask import Blueprint
from config_loader import load_general_config
from flask import send_from_directory, session
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from app import app
from qr_generator import generate_qr_code


conf_dir = os.path.join("..", "..", "conf")
conf_file_path = os.path.join(conf_dir, "settings.cfg")

usessl, port, host, cert, key, URL, City, login_basic, ssl_settings = load_general_config(conf_file_path)



def generate_pdf(construction_id, Construction, app):
    username = session.get('username')
    entry = Construction.query.get(construction_id)

    if entry:
        pdf_filename = f'Verkehrslage_{construction_id}_{date.today()}.pdf'
        pdf_path = os.path.join(app.config['PDF_FOLDER'], pdf_filename)

        app.logger.info(f"User: {username} create new PDF-File: {pdf_filename}")
        generate_pdf_file(entry, pdf_path)

        return send_from_directory(app.config['PDF_FOLDER'], pdf_filename, as_attachment=False)

    return 'Error: Construction not found', 404


def draw_multiline_text(canvas, text, x, y, max_width, font_size):
    lines = []
    words = text.split()
    current_line = words[0]

    for word in words[1:]:
        if canvas.stringWidth(current_line + ' ' + word, 'Helvetica', font_size) < max_width:
            current_line += ' ' + word
        else:
            lines.append(current_line)
            current_line = word

    lines.append(current_line)

    for line in lines:
        canvas.drawString(x, y, line)
        y -= font_size + 4  # Increase line spacing

    return y  # Return the updated y position

def generate_pdf_file(construction, filename):
    app.logger.debug("Start to produce PDF")
    latitude = construction.latitude
    longitude =construction.longitude
    description = f"TrafficHandler - {construction.title}"
    generate_qr_code(latitude, longitude, description, "qr_code.png")
    username = session.get('username')
    pdf_canvas = canvas.Canvas(filename, pagesize=A4)

    header_position = A4[1] - 50
    footer_position = 30

    logo_path = 'static/ERR-Logo_oT.png'
    pdf_canvas.drawImage(logo_path, A4[0] - 60, header_position - 20, width=50, height=50)

    pdf_canvas.setFont('Helvetica-Bold', 16)
    pdf_canvas.drawCentredString(A4[0] / 2, header_position, f'{construction.title} ')

    pdf_canvas.setFont('Helvetica', 10)
    pdf_canvas.drawCentredString(A4[0] / 2, header_position - 20, f'PDF erstellt am: {date.today()} von {username}')
    pdf_canvas.line(50, header_position - 30, A4[0] - 50, header_position - 30)


    content_start_position = header_position - 60
    pdf_canvas.setFont('Helvetica', 11)

    fields = [
        ('Title', construction.title),
        ('Beschreibung', construction.description),
        ('Straße', construction.strasse),
        ('PLZ', construction.plz),
        ('Ort', construction.ort),
        ('Startdatum', construction.start_date),
        ('Enddatum', construction.end_date),
        ('Breitengrad', construction.latitude),
        ('Längengrad', construction.longitude),
        ('Type', construction.type),
        ('Hinweis', 'Bitte die Angaben für das Fahrzeug beachten!'),
        ('Länge', construction.length),
        ('Breite', construction.width),
        ('Höhe', construction.height),
        ('Gewicht', construction.weight)
    ]
    app.logger.debug(fields)
    for field, value in fields:
        if field == 'Beschreibung':
            content_start_position = draw_multiline_text(pdf_canvas, f'{field}: {value}', 50, content_start_position, A4[0] - 100, 11)
        else:
            pdf_canvas.drawString(50, content_start_position, f'{field}: {value}')
        content_start_position -= 30

    content_start_position -=60

    pdf_canvas.drawString(50, content_start_position, "Googl Maps - QR-Code:")

    content_start_position -= 100

    qr_code_image = "qr_code.png"
    pdf_canvas.drawImage(qr_code_image, 50, content_start_position, width=90, height=90)

    pdf_canvas.line(50, footer_position, A4[0] - 50, footer_position)
    pdf_canvas.setFont('Helvetica', 10)
    pdf_canvas.drawCentredString(A4[0] / 2, footer_position + 10, f'Traffichandler Stadt: {City}  - Fahren Sie vorsichtig  - traffichandler.de')

    pdf_canvas.save()