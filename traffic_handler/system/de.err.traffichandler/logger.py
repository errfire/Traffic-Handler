#!/usr/bin/env python3
#ERR-FIRE
#Billel Meftah
import os
import logging
from logging.handlers import TimedRotatingFileHandler
import configparser

def initialize_logger():
    conf_dir = os.path.join("..", "..", "conf")
    config = configparser.ConfigParser()
    config.read(os.path.join(conf_dir, 'err-log-rotation.cfg'))

    current_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(current_dir)

    log_dir = os.path.join("..", "..", "logs")
    os.makedirs(log_dir, exist_ok=True)

    log_file_path = os.path.join(log_dir, "err_main.log")

    rotation_when = config.get('LogRotation', 'when', fallback='midnight')
    rotation_interval = config.getint('LogRotation', 'interval', fallback=1)
    backup_count = config.getint('LogRotation', 'backup_count', fallback=10)

    handler = TimedRotatingFileHandler(
        log_file_path,
        when=rotation_when,
        interval=rotation_interval,
        backupCount=backup_count
    )

    handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] > %(message)s'))

    logger = logging.getLogger()
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

    logger.info('Logger started')
    logger.info(f'Logger Version {logging.__version__}')
    Test="Only Test the Loggerlevel."
    logger.error(Test)
    logger.critical(Test)
    logger.debug(Test)
    logger.info("Application run now")
    logger.info("The following Settings for Log rotation: ")
    logger.info(f"When: {rotation_when} - Interval: {rotation_interval} - BackupCount: {backup_count}")

if __name__ == "__main__":
    initialize_logger()
