import ssl
import socket
import datetime
import OpenSSL
from django.utils import timezone
from scanner.models import Domain, SSLCertificate

def check_ssl_certificate(domain_id):
    """
    Check SSL certificate for a domain
    
    Args:
        domain_id: ID of the domain to check
        
    Returns:
        SSLCertificate object
    """
    try:
        domain = Domain.objects.get(id=domain_id)
    except Domain.DoesNotExist:
        return None
    
    domain_name = domain.name
    
    try:
        # Connect to the domain and get the certificate
        context = ssl.create_default_context()
        conn = context.wrap_socket(
            socket.socket(socket.AF_INET),
            server_hostname=domain_name
        )
        conn.settimeout(5.0)
        conn.connect((domain_name, 443))
        ssl_info = conn.getpeercert()
        
        # Parse certificate information
        issuer = dict(x[0] for x in ssl_info['issuer'])
        issuer_name = issuer.get('organizationName', issuer.get('commonName', 'Unknown'))
        
        valid_from = datetime.datetime.strptime(ssl_info['notBefore'], '%b %d %H:%M:%S %Y %Z')
        valid_until = datetime.datetime.strptime(ssl_info['notAfter'], '%b %d %H:%M:%S %Y %Z')
        
        # Check if certificate is valid
        now = timezone.now()
        is_valid = valid_from <= now <= valid_until
        
        # Create or update SSL certificate record
        ssl_cert, created = SSLCertificate.objects.update_or_create(
            domain=domain,
            defaults={
                'issuer': issuer_name,
                'valid_from': valid_from,
                'valid_until': valid_until,
                'is_valid': is_valid
            }
        )
        
        return ssl_cert
    
    except (socket.gaierror, socket.timeout, ssl.SSLError, ConnectionRefusedError) as e:
        # Handle connection errors
        print(f"Error checking SSL for {domain_name}: {e}")
        return None

def check_ssl_info(domain_name):
    """
    Check SSL certificate information for a domain
    
    Args:
        domain_name: Name of the domain to check
        
    Returns:
        Dictionary with SSL information
    """
    try:
        # Connect to the domain and get the certificate
        context = ssl.create_default_context()
        conn = context.wrap_socket(
            socket.socket(socket.AF_INET),
            server_hostname=domain_name
        )
        conn.settimeout(5.0)
        conn.connect((domain_name, 443))
        ssl_info = conn.getpeercert()
        
        # Parse certificate information
        issuer = dict(x[0] for x in ssl_info['issuer'])
        issuer_name = issuer.get('organizationName', issuer.get('commonName', 'Unknown'))
        
        valid_from = datetime.datetime.strptime(ssl_info['notBefore'], '%b %d %H:%M:%S %Y %Z')
        valid_until = datetime.datetime.strptime(ssl_info['notAfter'], '%b %d %H:%M:%S %Y %Z')
        
        return {
            'has_ssl': True,
            'issuer': issuer_name,
            'valid_from': valid_from,
            'ssl_expires_date': valid_until,
            'is_valid': valid_from <= timezone.now() <= valid_until
        }
    
    except (socket.gaierror, socket.timeout, ssl.SSLError, ConnectionRefusedError) as e:
        # Handle connection errors
        print(f"Error checking SSL for {domain_name}: {e}")
        return {
            'has_ssl': False,
            'error': str(e)
        }

def get_domain_info(domain_name):
    """
    Get WHOIS information for a domain
    
    Args:
        domain_name: Name of the domain to check
        
    Returns:
        Dictionary with domain information
    """
    try:
        import whois
        domain_info = whois.whois(domain_name)
        
        return {
            'registrar': domain_info.registrar,
            'creation_date': domain_info.creation_date,
            'expiration_date': domain_info.expiration_date,
            'name_servers': domain_info.name_servers
        }
    except Exception as e:
        print(f"Error getting domain info for {domain_name}: {e}")
        return {
            'registrar': None,
            'creation_date': None,
            'expiration_date': None,
            'name_servers': None
        }

