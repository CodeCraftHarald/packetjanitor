import os
import subprocess

# Make migrations
subprocess.run(['python', 'manage.py', 'makemigrations', 'core', 'whitelist', 'reports', 'dashboard'])

# Apply migrations
subprocess.run(['python', 'manage.py', 'migrate'])

# Create superuser (uncomment to create a superuser)
# subprocess.run(['python', 'manage.py', 'createsuperuser']) 