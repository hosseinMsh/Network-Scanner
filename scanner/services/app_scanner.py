import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import re
from scanner.models import Domain, Application

def detect_technology(domain_id):
    """
    Detect technologies used on a domain
    
    Args:
        domain_id: ID of the domain to scan
        
    Returns:
        Dictionary of detected technologies
    """
    try:
        domain = Domain.objects.get(id=domain_id)
    except Domain.DoesNotExist:
        return None
    
    domain_name = domain.name
    url = f"https://{domain_name}"
    
    try:
        # Fetch the website
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        
        # Parse HTML
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Initialize results
        technologies = {
            'cms': None,
            'framework': None,
            'server': None,
            'frontend': None,
            'detected_apps': []
        }
        
        # Check response headers
        server = response.headers.get('Server')
        if server:
            technologies['server'] = server
        
        # Check for common frameworks and CMS
        # Django
        if 'csrftoken' in response.cookies or 'django' in response.text.lower():
            technologies['framework'] = 'Django'
            technologies['detected_apps'].append('Django')
        
        # Flask
        if 'flask' in response.text.lower():
            technologies['framework'] = 'Flask'
            technologies['detected_apps'].append('Flask')
        
        # Laravel
        if 'laravel' in response.text.lower() or 'csrf-token' in response.text.lower():
            technologies['framework'] = 'Laravel'
            technologies['detected_apps'].append('Laravel')
        
        # WordPress
        if 'wp-content' in response.text or 'wordpress' in response.text.lower():
            technologies['cms'] = 'WordPress'
            technologies['detected_apps'].append('WordPress')
        
        # React
        if 'react' in response.text.lower() or 'reactjs' in response.text.lower():
            technologies['frontend'] = 'React'
            technologies['detected_apps'].append('React')
        
        # Angular
        if 'ng-' in response.text or 'angular' in response.text.lower():
            technologies['frontend'] = 'Angular'
            technologies['detected_apps'].append('Angular')
        
        # Create or update application records
        for tech in technologies['detected_apps']:
            tech_type = 'other'
            if tech.lower() in [choice[0] for choice in Application.TechnologyType.choices]:
                tech_type = tech.lower()
            
            Application.objects.update_or_create(
                server=domain.server,
                domain=domain,
                name=f"{tech} on {domain_name}",
                defaults={
                    'technology_type': tech_type,
                    'description': f"Detected {tech} on {domain_name}"
                }
            )
        
        return technologies
    
    except requests.RequestException as e:
        print(f"Error scanning {url}: {e}")
        return None

