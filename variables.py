import os
from datetime import datetime

USERNAME = os.environ.get('EMAIL')
PASSWORD = os.environ.get('PASSWORD')
DEST_EMAIL = os.environ.get('DEST_EMAIL')

today = datetime.now().strftime("%B %d, %Y")