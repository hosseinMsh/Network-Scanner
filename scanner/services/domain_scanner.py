import socket
import dns.resolver
import requests
from bs4 import BeautifulSoup
import json
import re
from urllib.parse import urlparse

def retrieve_ipv4_from_domain(domain_name):
    """
    Retrieve IPv4 address from domain name
    
    Args:
        domain_name: Name of the domain to check
        
    Returns:
        IPv4 address as string or None if not found
    """
    try:
        ip_address = socket.gethostbyname(domain_name)
        return ip_address
    except socket.gaierror:
        return None

def retrieve_ipv6_from_domain(domain_name):
    """
    Retrieve IPv6 address from domain name
    
    Args:
        domain_name: Name of the domain to check
        
    Returns:
        IPv6 address as string or None if not found
    """
    try:
        answers = dns.resolver.resolve(domain_name, 'AAAA')
        for rdata in answers:
            return str(rdata)
        return None
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
        return None

def detect_technologies(domain_name):
    """
    Detect technologies used by a domain
    
    Args:
        domain_name: Name of the domain to check
        
    Returns:
        Dictionary with detected technologies
    """
    url = f"https://{domain_name}"
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Initialize results
        results = {
            'detected_apps': [],
            'headers': dict(response.headers),
            'meta_tags': {}
        }
        
        # Check for common technologies
        # WordPress
        if soup.select('meta[name="generator"][content*="WordPress"]') or soup.select('link[rel="https://api.w.org/"]'):
            results['detected_apps'].append('WordPress')
        
        # Drupal
        if soup.select('meta[name="generator"][content*="Drupal"]') or 'Drupal.settings' in response.text:
            results['detected_apps'].append('Drupal')
        
        # Joomla
        if soup.select('meta[name="generator"][content*="Joomla"]') or '/media/jui/' in response.text:
            results['detected_apps'].append('Joomla')
        
        # Bootstrap
        if soup.select('link[href*="bootstrap"]') or 'bootstrap' in response.text.lower():
            results['detected_apps'].append('Bootstrap')
        
        # jQuery
        if 'jquery' in response.text.lower():
            results['detected_apps'].append('jQuery')
        
        # React
        if 'react' in response.text.lower() and 'reactdom' in response.text.lower():
            results['detected_apps'].append('React')
        
        # Angular
        if 'ng-app' in response.text.lower() or 'angular' in response.text.lower():
            results['detected_apps'].append('Angular')
        
        # Vue.js
        if 'vue' in response.text.lower() and ('v-if' in response.text.lower() or 'v-for' in response.text.lower()):
            results['detected_apps'].append('Vue.js')
        
        # Collect meta tags
        for meta in soup.select('meta'):
            if meta.get('name') and meta.get('content'):
                results['meta_tags'][meta['name']] = meta['content']
        
        return results
    
    except requests.exceptions.RequestException as e:
        print(f"Error detecting technologies for {domain_name}: {e}")
        return {
            'detected_apps': [],
            'error': str(e)
        }

def get_dns_records(domain_name):
    """
    Get DNS records for a domain
    
    Args:
        domain_name: Name of the domain to check
        
    Returns:
        Dictionary with DNS records
    """
    records = {}
    
    try:
        # A records
        try:
            answers = dns.resolver.resolve(domain_name, 'A')
            records['A'] = [str(rdata) for rdata in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
            records['A'] = []
        
        # AAAA records
        try:
            answers = dns.resolver.resolve(domain_name, 'AAAA')
            records['AAAA'] = [str(rdata) for rdata in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
            records['AAAA'] = []
        
        # MX records
        try:
            answers = dns.resolver.resolve(domain_name, 'MX')
            records['MX'] = [str(rdata.exchange) for rdata in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
            records['MX'] = []
        
        # NS records
        try:
            answers = dns.resolver.resolve(domain_name, 'NS')
            records['NS'] = [str(rdata) for rdata in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
            records['NS'] = []
        
        # TXT records
        try:
            answers = dns.resolver.resolve(domain_name, 'TXT')
            records['TXT'] = [str(rdata) for rdata in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
            records['TXT'] = []
        
        return records
    
    except Exception as e:
        print(f"Error getting DNS records for {domain_name}: {e}")
        return {
            'error': str(e)
        }

def get_http_headers(domain_name):
    """
    Get HTTP headers for a domain
    
    Args:
        domain_name: Name of the domain to check
        
    Returns:
        Dictionary with HTTP headers
    """
    url = f"https://{domain_name}"
    try:
        response = requests.head(url, timeout=10)
        return dict(response.headers)
    except requests.exceptions.RequestException as e:
        print(f"Error getting HTTP headers for {domain_name}: {e}")
        return {
            'error': str(e)
        }

