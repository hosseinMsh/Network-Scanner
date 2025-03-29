from celery import shared_task
from .services.port_scanner import scan_server_ports
from .services.ssl_checker import check_ssl_certificate
from .services.app_scanner import detect_technology
from django.utils import timezone
from .models import Server, Domain

@shared_task
def scan_server_ports_task(server_id, port_range="1-1024", user_id=None):
    """
    Celery task to scan ports on a server
    """
    return scan_server_ports(server_id, port_range, user_id)

@shared_task
def check_ssl_certificate_task(domain_id):
    """
    Celery task to check SSL certificate for a domain
    """
    return check_ssl_certificate(domain_id)

@shared_task
def detect_technology_task(domain_id):
    """
    Celery task to detect technologies used on a domain
    """
    return detect_technology(domain_id)

@shared_task
def scheduled_port_scan():
    """
    Scheduled task to scan ports on all servers
    """
    servers = Server.objects.all()
    for server in servers:
        scan_server_ports_task.delay(server.id, "1-1024", server.created_by_id)
        server.last_scanned = timezone.now()
        server.save()

@shared_task
def scheduled_ssl_check():
    """
    Scheduled task to check SSL certificates for all domains
    """
    domains = Domain.objects.all()
    for domain in domains:
        check_ssl_certificate_task.delay(domain.id)

