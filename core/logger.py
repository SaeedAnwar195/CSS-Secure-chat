import os
import logging
from logging.handlers import RotatingFileHandler

class Logger:
    def __init__(self, app_name='Cryptogram'):
        self.app_name = app_name
        self.log_dir = 'logs'
        self.log_file = os.path.join(self.log_dir, 'app.log')
        self._setup_logger()

    def _setup_logger(self):
        # Create logs directory if it doesn't exist
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)

        # Create logger instance
        self.logger = logging.getLogger(self.app_name)
        self.logger.setLevel(logging.DEBUG)

        # Create formatter
        formatter = logging.Formatter(
            '[%(asctime)s] [%(levelname)s] [%(module)s:%(lineno)d] - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

        # Setup file handler with rotation
        file_handler = RotatingFileHandler(
            self.log_file,
            maxBytes=10485760,  # 10MB
            backupCount=5
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)

        # Add file handler to logger
        self.logger.addHandler(file_handler)

    def get_logger(self):
        return self.logger

# Create global logger instance
app_logger = Logger().get_logger()
