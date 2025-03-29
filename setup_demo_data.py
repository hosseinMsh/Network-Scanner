#!/usr/bin/env python
"""
Script to set up demo data for PingHub
"""
import os
import sys
import django

# Set up Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'network_scanner.settings')
django.setup()

from django.contrib.auth.models import User
from scanner.models import Network, Server, Domain, Person, Application
from django.utils import timezone

def create_demo_data():
    """Create demo data for PingHub"""
    print("Creating demo data for PingHub...")
    
    # Create superuser if it doesn't exist
    if not User.objects.filter(username='admin').exists():
        User.objects.create_superuser('admin', 'admin@example.com', 'adminpassword')
        print("Created superuser 'admin' with password 'adminpassword'")
    
    # Get or create admin user
    admin_user = User.objects.get(username='admin')
    
    # Create representatives
    tech_rep, _ = Person.objects.get_or_create(
        name="John Doe",
        email="john.doe@example.com",
        defaults={
            'phone': '+1234567890',
            'position': 'IT Manager',
            'company': 'Example Corp'
        }
    )
    
    legal_rep, _ = Person.objects.get_or_create(
        name="Jane Smith",
        email="jane.smith@example.com",
        defaults={
            'phone': '+1987654321',
            'position': 'Legal Counsel',
            'company': 'Example Corp'
        }
    )
    
    # Create network
    network, _ = Network.objects.get_or_create(
        name="Demo Network",
        defaults={
            'description': "Network for demonstration purposes",
            'ip_range': "192.168.1.0/24",
            'created_by': admin_user
        }
    )
    
    # Create servers
    web_server, _ = Server.objects.get_or_create(
        name="Web Server",
        ip_address="192.168.1.10",
        network=network,
        defaults={
            'hostname': 'web.example.com',
            'operating_system': 'Ubuntu',
            'os_version': '22.04 LTS',
            'cpu_cores': 4,
            'ram_gb': 8,
            'disk_space_gb': 500,
            'technical_representative': tech_rep,
            'legal_representative': legal_rep,
            'created_by': admin_user
        }
    )
    
    db_server, _ = Server.objects.get_or_create(
        name="Database Server",
        ip_address="192.168.1.20",
        network=network,
        defaults={
            'hostname': 'db.example.com',
            'operating_system': 'CentOS',
            'os_version': '8',
            'cpu_cores': 8,
            'ram_gb': 16,
            'disk_space_gb': 1000,
            'technical_representative': tech_rep,
            'legal_representative': legal_rep,
            'created_by': admin_user
        }
    )
    
    # Create domains
    main_domain, _ = Domain.objects.get_or_create(
        name="example.com",
        server=web_server,
        defaults={
            'technical_representative': tech_rep,
            'registrar': 'GoDaddy',
            'registration_date': timezone.now() - timezone.timedelta(days=365),
            'expiration_date': timezone.now() + timezone.timedelta(days=365),
            'status': 'active'
        }
    )
    
    blog_domain, _ = Domain.objects.get_or_create(
        name="blog.example.com",
        server=web_server,
        defaults={
            'technical_representative': tech_rep,
            'registrar': 'GoDaddy',
            'registration_date': timezone.now() - timezone.timedelta(days=180),
            'expiration_date': timezone.now() + timezone.timedelta(days=180),
            'status': 'active'
        }
    )
    
    # Create applications
    Application.objects.get_or_create(
        name="WordPress Blog",
        server=web_server,
        domain=blog_domain,
        defaults={
            'technology_type': 'wordpress',
            'version': '6.2',
            'description': 'Company blog running on WordPress',
            'technical_representative': tech_rep
        }
    )
    
    Application.objects.get_or_create(
        name="Main Website",
        server=web_server,
        domain=main_domain,
        defaults={
            'technology_type': 'django',
            'version': '4.2',
            'description': 'Main company website built with Django',
            'technical_representative': tech_rep
        }
    )
    
    Application.objects.get_or_create(
        name="PostgreSQL Database",
        server=db_server,
        defaults={
            'technology_type': 'other',
            'version': '14.5',
            'description': 'Main database server',
            'technical_representative': tech_rep
        }
    )
    
    print("Demo data created successfully!")

if __name__ == "__main__":
    create_demo_data()

