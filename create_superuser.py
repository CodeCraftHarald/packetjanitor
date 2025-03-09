import os
import django
import getpass

# Set up Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'packetjanitor.settings')
django.setup()

from django.contrib.auth.models import User

def create_superuser():
    print("Create PacketJanitor Admin User")
    print("==============================")
    
    # Check if superuser already exists
    if User.objects.filter(is_superuser=True).exists():
        print("A superuser already exists. Do you want to create another one? (y/n)")
        choice = input().lower()
        if choice != 'y':
            print("Superuser creation cancelled.")
            return
    
    # Get username
    while True:
        username = input("Username: ")
        if not username:
            print("Username cannot be empty.")
            continue
        if User.objects.filter(username=username).exists():
            print(f"User '{username}' already exists. Please choose another username.")
            continue
        break
    
    # Get email
    email = input("Email (optional): ")
    
    # Get password
    while True:
        password = getpass.getpass("Password: ")
        if not password:
            print("Password cannot be empty.")
            continue
        
        password_confirm = getpass.getpass("Confirm password: ")
        if password != password_confirm:
            print("Passwords do not match. Please try again.")
            continue
        
        break
    
    # Create superuser
    try:
        user = User.objects.create_superuser(username=username, email=email, password=password)
        print(f"\nSuperuser '{username}' created successfully!")
        print("You can now log in to the application.")
    except Exception as e:
        print(f"Error creating superuser: {str(e)}")

if __name__ == "__main__":
    create_superuser() 