# PacketJanitor - Network Traffic Monitoring and Analysis

PacketJanitor is a powerful yet user-friendly network traffic monitoring application built with Django and Scapy. It provides deep insights into network activity while maintaining a focus on user privacy and ethical considerations.

## Features

- **Real-time Network Monitoring**: Capture and analyze network packets in real-time
- **User-friendly Dashboard**: Dark-themed interface with intuitive visualizations
- **Application Whitelisting**: Exclude trusted applications from monitoring
- **Scheduled Reporting**: Generate hourly reports on network activity
- **Privacy-focused**: Local processing with emphasis on data protection
- **Educational Components**: Learn about networking concepts through interactive elements

## Requirements

- Python 3.9+
- Administrative privileges (for packet capture)
- Django 5.1+
- Scapy 2.6+
- Additional dependencies listed in requirements.txt

## Installation

1. Clone the repository:
```
git clone https://github.com/yourusername/packetjanitor.git
cd packetjanitor
```

2. Create a virtual environment:
```
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```
pip install -r requirements.txt
```

4. Run database migrations:
```
python manage.py migrate
```

5. Create a superuser (for admin access):
```
python manage.py createsuperuser
```

6. Run the development server:
```
python manage.py runserver
```

## Usage

1. Start the application:
```
python manage.py runserver
```

2. Access the web interface at http://localhost:8000

3. Login with your superuser credentials

4. Begin monitoring network traffic through the dashboard

## Ethical Guidelines

- **Privacy**: PacketJanitor is designed to respect user privacy and data protection laws
- **Transparency**: The application is transparent about its functionality and data handling
- **Security**: All collected data is stored securely and locally

## Architecture

PacketJanitor is built with a modular design pattern:

- **Core**: Handles packet capture and analysis using Scapy
- **Dashboard**: Provides the main user interface and visualization
- **Reports**: Manages report generation and storage
- **Whitelist**: Handles application whitelisting functionality

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Disclaimer

PacketJanitor is designed for legitimate network analysis and monitoring. Users are responsible for ensuring compliance with local laws and regulations regarding network monitoring. 