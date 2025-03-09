import os
import django

# Set up Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'packetjanitor.settings')
django.setup()

from django.contrib.auth.models import User

# Define credentials
USERNAME = 'admin'
PASSWORD = 'adminpassword'
EMAIL = 'admin@example.com'

# Check if user exists and delete if necessary
try:
    user = User.objects.get(username=USERNAME)
    print(f"User '{USERNAME}' already exists. Deleting...")
    user.delete()
    print(f"User '{USERNAME}' deleted.")
except User.DoesNotExist:
    pass

# Create new superuser
print(f"Creating new superuser '{USERNAME}'...")
User.objects.create_superuser(username=USERNAME, email=EMAIL, password=PASSWORD)
print(f"Superuser '{USERNAME}' created successfully!")
print(f"\nYou can now log in with:")
print(f"Username: {USERNAME}")
print(f"Password: {PASSWORD}") 