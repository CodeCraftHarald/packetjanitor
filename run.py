import os
import subprocess
import webbrowser
import time

print("Starting PacketJanitor...")

# Run the Django development server
server_process = subprocess.Popen(['python', 'manage.py', 'runserver'])

# Wait a moment for the server to start
time.sleep(2)

# Open the browser
webbrowser.open('http://localhost:8000')

print("PacketJanitor is running at http://localhost:8000")
print("Press Ctrl+C to stop the server")

try:
    # Keep the script running until interrupted
    server_process.wait()
except KeyboardInterrupt:
    # Handle Ctrl+C gracefully
    print("\nStopping PacketJanitor...")
    server_process.terminate()
    server_process.wait()
    print("PacketJanitor stopped") 