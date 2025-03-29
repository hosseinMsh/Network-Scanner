# PingHub - Network and Server Monitoring

PingHub is a comprehensive Django application for network and server scanning with a dashboard to monitor and manage your infrastructure. This solution includes scanning ports, IPs, domains, SSL certificates, and installed applications on servers.

![PingHub Dashboard](docs/images/dashboard.png)

## Features

- **Network Management**: Add and manage networks with IP ranges
- **Server Monitoring**: Track server details, specifications, and installed applications
- **Domain Management**: Monitor domains, check SSL certificates, and detect technologies
- **Port Scanning**: Scan servers for open ports and services
- **Vulnerability Tracking**: Record and manage vulnerabilities with severity levels
- **Reporting**: Generate comprehensive reports for networks, servers, and domains
- **User Management**: Control access with user accounts and permissions

## Quick Start

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/pinghub.git
   cd pinghub
   ```

2. Create a virtual environment and activate it:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

4. Create a `.env` file based on `.env.example`:
   ```
   cp .env.example .env
   ```

5. Run migrations:
   ```
   python manage.py migrate
   ```

6. Create a superuser:
   ```
   python manage.py createsuperuser
   ```

7. Collect static files:
   ```
   # On Linux/Mac:
   ./collect_static.sh
   
   # On Windows:
   collect_static.bat
   ```

8. Run the development server:
   ```
   # On Linux/Mac:
   ./run.sh
   
   # On Windows:
   run.bat
   ```

9. Access the application at http://localhost:8000

## Docker Deployment

1. Build and run with Docker Compose:
   ```
   docker-compose up -d
   ```

2. Access the application at http://localhost:8000

## Demo Data

To populate the application with demo data for testing:

