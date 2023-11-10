import os
from datetime import datetime

USERNAME = os.environ.get('EMAIL')
PASSWORD = os.environ.get('PASSWORD')

today = datetime.now().strftime("%B %d, %Y")