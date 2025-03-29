#!/usr/bin/env python
"""
Script to check if all dependencies are installed correctly
"""
import sys
import importlib
import subprocess
import os

# List of required Python packages
REQUIRED_PACKAGES = [
    'django',
    'djangorestframework',
    'django_crispy_forms',
    'crispy_bootstrap5',
    'celery',
    'redis',
    'requests',
    'bs4',  # BeautifulSoup
    'OpenSSL',
    'dns',  # dnspython
    'whois',
    'weasyprint',
    'reportlab',
    'dotenv',
]

# List of required system dependencies
SYSTEM_DEPENDENCIES = [
    ('nmap', 'nmap --version', 'Nmap is required for port scanning'),
    ('redis', 'redis-cli --version', 'Redis is required for Celery task queue'),
]

def check_python_packages():
    """Check if all required Python packages are installed"""
    print("Checking Python packages...")
    missing_packages = []
    
    for package in REQUIRED_PACKAGES:
        try:
            importlib.import_module(package)
            print(f"✅ {package}")
        except ImportError:
            print(f"❌ {package}")
            missing_packages.append(package)
    
    return missing_packages

def check_system_dependencies():
    """Check if all required system dependencies are installed"""
    print("\nChecking system dependencies...")
    missing_dependencies = []
    
    for name, command, message in SYSTEM_DEPENDENCIES:
        try:
            subprocess.run(command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            print(f"✅ {name}")
        except (subprocess.CalledProcessError, FileNotFoundError):
            print(f"❌ {name} - {message}")
            missing_dependencies.append(name)
    
    return missing_dependencies

def check_django_configuration():
    """Check if Django is configured correctly"""
    print("\nChecking Django configuration...")
    
    # Check if settings module is configured
    try:
        os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'network_scanner.settings')
        import django
        django.setup()
        from django.conf import settings
        print(f"✅ Django settings")
    except Exception as e:
        print(f"❌ Django settings - {str(e)}")
        return False
    
    # Check database connection
    try:
        from django.db import connection
        connection.ensure_connection()
        print(f"✅ Database connection")
    except Exception as e:
        print(f"❌ Database connection - {str(e)}")
        return False
    
    # Check if migrations are applied
    try:
        from django.db.migrations.recorder import MigrationRecorder
        unapplied = MigrationRecorder.Migration.objects.filter(applied=False).count()
        if unapplied > 0:
            print(f"⚠️ You have {unapplied} unapplied migrations")
        else:
            print(f"✅ Migrations")
    except Exception as e:
        print(f"❌ Migrations check - {str(e)}")
    
    return True

def main():
    """Main function"""
    print("PingHub Dependency Checker")
    print("=========================\n")
    
    # Check Python packages
    missing_packages = check_python_packages()
    
    # Check system dependencies
    missing_dependencies = check_system_dependencies()
    
    # Check Django configuration
    django_ok = check_django_configuration()
    
    # Print summary
    print("\nSummary:")
    if not missing_packages and not missing_dependencies and django_ok:
        print("✅ All dependencies are installed correctly!")
        return 0
    else:
        if missing_packages:
            print(f"❌ Missing Python packages: {', '.join(missing_packages)}")
            print("   Install them with: pip install -r requirements.txt")
        
        if missing_dependencies:
            print(f"❌ Missing system dependencies: {', '.join(missing_dependencies)}")
            print("   Install them using your system's package manager")
        
        if not django_ok:
            print("❌ Django configuration issues detected")
        
        return 1

if __name__ == "__main__":
    sys.exit(main())

