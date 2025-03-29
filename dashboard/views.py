from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.db.models import Count, Q
from django.utils import timezone
from datetime import timedelta
from scanner.models import (
    Network, Server, Domain, Application, 
    SSLCertificate, PortScan, Vulnerability
)

@login_required
def index(request):
    """Dashboard index view with modern template"""
    # Get counts for dashboard stats
    networks_count = Network.objects.count()
    servers_count = Server.objects.count()
    domains_count = Domain.objects.count()
    applications_count = Application.objects.count()
    
    # Get recent scans
    recent_port_scans = PortScan.objects.order_by('-scan_date')[:5]
    
    # Get servers with vulnerabilities
    vulnerable_servers = Server.objects.annotate(
        vuln_count=Count('vulnerabilities')
    ).filter(vuln_count__gt=0).order_by('-vuln_count')[:5]
    
    # Get expiring SSL certificates (within 30 days)
    thirty_days_from_now = timezone.now() + timedelta(days=30)
    expiring_certs = SSLCertificate.objects.filter(
        valid_until__lte=thirty_days_from_now,
        is_valid=True
    ).order_by('valid_until')[:5]
    
    # Get vulnerability severity distribution
    vulnerability_stats = Vulnerability.objects.values('severity').annotate(
        count=Count('id')
    ).order_by('severity')
    
    # Prepare data for charts
    vulnerability_data = {
        'labels': [stat['severity'].capitalize() for stat in vulnerability_stats],
        'data': [stat['count'] for stat in vulnerability_stats],
    }
    
    # Get servers by OS
    servers_by_os = Server.objects.values('operating_system').annotate(
        count=Count('id')
    ).order_by('-count')
    
    os_data = {
        'labels': [os['operating_system'] or 'Unknown' for os in servers_by_os],
        'data': [os['count'] for os in servers_by_os],
    }
    
    context = {
        'networks_count': networks_count,
        'servers_count': servers_count,
        'domains_count': domains_count,
        'applications_count': applications_count,
        'recent_port_scans': recent_port_scans,
        'vulnerable_servers': vulnerable_servers,
        'expiring_certs': expiring_certs,
        'vulnerability_data': vulnerability_data,
        'os_data': os_data,
    }
    
    return render(request, 'dashboard/index_modern.html', context)

