from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import HttpResponse
from django.template.loader import render_to_string
from django.utils import timezone
import json
import csv
import io
from weasyprint import HTML
from .models import Report
from scanner.models import Network, Server, Domain, Vulnerability, PortScanResult

@login_required
def report_list(request):
    """View for listing reports"""
    if request.user.is_superuser:
        reports = Report.objects.all().order_by('-created_at')
    else:
        reports = Report.objects.filter(created_by=request.user).order_by('-created_at')
    
    context = {
        'reports': reports
    }
    return render(request, 'reports/report_list.html', context)

@login_required
def report_detail(request, pk):
    """View for report details"""
    report = get_object_or_404(Report, pk=pk)
    
    # Check if user has permission to view this report
    if not request.user.is_superuser and report.created_by != request.user:
        messages.error(request, "You don't have permission to view this report.")
        return redirect('reports:report_list')
    
    context = {
        'report': report,
        'content': report.content_json
    }
    return render(request, 'reports/report_detail.html', context)

@login_required
def generate_network_report(request, network_id):
    """View for generating a network report"""
    network = get_object_or_404(Network, pk=network_id)
    
    # Check if user has permission
    if not request.user.is_superuser and network.created_by != request.user:
        messages.error(request, "You don't have permission to generate a report for this network.")
        return redirect('scanner:network_list')
    
    # Gather data for the report
    servers = network.servers.all()
    server_count = servers.count()
    domains = Domain.objects.filter(server__in=servers)
    domain_count = domains.count()
    
    # Count vulnerabilities by severity
    vulnerabilities = Vulnerability.objects.filter(server__in=servers)
    vuln_by_severity = {
        'critical': vulnerabilities.filter(severity='critical').count(),
        'high': vulnerabilities.filter(severity='high').count(),
        'medium': vulnerabilities.filter(severity='medium').count(),
        'low': vulnerabilities.filter(severity='low').count(),
        'info': vulnerabilities.filter(severity='info').count(),
    }
    
    # Create report content
    report_content = {
        'network_name': network.name,
        'network_description': network.description,
        'ip_range': network.ip_range,
        'server_count': server_count,
        'domain_count': domain_count,
        'vulnerabilities': vuln_by_severity,
        'servers': [],
        'generated_at': timezone.now().isoformat()
    }
    
    # Add server details
    for server in servers:
        server_domains = server.domains.all()
        server_vulns = server.vulnerabilities.all()
        
        server_data = {
            'id': server.id,
            'name': server.name,
            'ip_address': server.ip_address,
            'operating_system': server.operating_system,
            'cpu_cores': server.cpu_cores,
            'ram_gb': server.ram_gb,
            'disk_space_gb': server.disk_space_gb,
            'domains': [{'id': d.id, 'name': d.name} for d in server_domains],
            'vulnerabilities': [
                {
                    'id': v.id,
                    'title': v.title,
                    'severity': v.severity,
                    'is_fixed': v.is_fixed
                } for v in server_vulns
            ]
        }
        report_content['servers'].append(server_data)
    
    # Create report record
    report = Report.objects.create(
        title=f"Network Report: {network.name}",
        report_type=Report.ReportType.NETWORK,
        network=network,
        description=f"Comprehensive report for network {network.name}",
        created_by=request.user,
        content_json=report_content
    )
    
    messages.success(request, f"Report generated for network {network.name}.")
    return redirect('reports:report_detail', pk=report.pk)

@login_required
def generate_server_report(request, server_id):
    """View for generating a server report"""
    server = get_object_or_404(Server, pk=server_id)
    
    # Check if user has permission
    if not request.user.is_superuser and server.created_by != request.user:
        messages.error(request, "You don't have permission to generate a report for this server.")
        return redirect('scanner:server_list')
    
    # Gather data for the report
    domains = server.domains.all()
    applications = server.applications.all()
    vulnerabilities = server.vulnerabilities.all()
    
    # Get latest port scan results
    latest_port_scan = server.port_scans.order_by('-scan_date').first()
    open_ports = []
    if latest_port_scan:
        open_ports = PortScanResult.objects.filter(
            port_scan=latest_port_scan,
            status='open'
        )
    
    # Create report content
    report_content = {
        'server_name': server.name,
        'ip_address': server.ip_address,
        'hostname': server.hostname,
        'operating_system': server.operating_system,
        'os_version': server.os_version,
        'cpu_cores': server.cpu_cores,
        'ram_gb': server.ram_gb,
        'disk_space_gb': server.disk_space_gb,
        'domains': [{'id': d.id, 'name': d.name} for d in domains],
        'applications': [
            {
                'id': a.id,
                'name': a.name,
                'technology_type': a.get_technology_type_display(),
                'version': a.version
            } for a in applications
        ],
        'vulnerabilities': [
            {
                'id': v.id,
                'title': v.title,
                'severity': v.severity,
                'cve_id': v.cve_id,
                'is_fixed': v.is_fixed
            } for v in vulnerabilities
        ],
        'open_ports': [
            {
                'port_number': p.port_number,
                'protocol': p.protocol,
                'service': p.service
            } for p in open_ports
        ],
        'generated_at': timezone.now().isoformat()
    }
    
    # Create report record
    report = Report.objects.create(
        title=f"Server Report: {server.name}",
        report_type=Report.ReportType.SERVER,
        server=server,
        description=f"Comprehensive report for server {server.name}",
        created_by=request.user,
        content_json=report_content
    )
    
    messages.success(request, f"Report generated for server {server.name}.")
    return redirect('reports:report_detail', pk=report.pk)

@login_required
def generate_domain_report(request, domain_id):
    """View for generating a domain report"""
    domain = get_object_or_404(Domain, pk=domain_id)
    
    # Check if user has permission
    if not request.user.is_superuser and domain.server.created_by != request.user:
        messages.error(request, "You don't have permission to generate a report for this domain.")
        return redirect('scanner:domain_list')
    
    # Gather data for the report
    applications = domain.applications.all()
    ssl_certificates = domain.ssl_certificates.all().order_by('-created_at')
    
    # Create report content
    report_content = {
        'domain_name': domain.name,
        'server_name': domain.server.name,
        'server_ip': domain.server.ip_address,
        'registrar': domain.registrar,
        'registration_date': domain.registration_date.isoformat() if domain.registration_date else None,
        'expiration_date': domain.expiration_date.isoformat() if domain.expiration_date else None,
        'technical_representative': domain.technical_representative.name if domain.technical_representative else None,
        'applications': [
            {
                'id': a.id,
                'name': a.name,
                'technology_type': a.get_technology_type_display(),
                'version': a.version
            } for a in applications
        ],
        'ssl_certificates': [
            {
                'id': s.id,
                'issuer': s.issuer,
                'valid_from': s.valid_from.isoformat(),
                'valid_until': s.valid_until.isoformat(),
                'is_valid': s.is_valid,
                'days_until_expiry': s.days_until_expiry
            } for s in ssl_certificates
        ],
        'generated_at': timezone.now().isoformat()
    }
    
    # Create report record
    report = Report.objects.create(
        title=f"Domain Report: {domain.name}",
        report_type=Report.ReportType.DOMAIN,
        domain=domain,
        description=f"Comprehensive report for domain {domain.name}",
        created_by=request.user,
        content_json=report_content
    )
    
    messages.success(request, f"Report generated for domain {domain.name}.")
    return redirect('reports:report_detail', pk=report.pk)

@login_required
def export_report_pdf(request, pk):
    """Export report as PDF"""
    report = get_object_or_404(Report, pk=pk)
    
    # Check if user has permission
    if not request.user.is_superuser and report.created_by != request.user:
        messages.error(request, "You don't have permission to export this report.")
        return redirect('reports:report_list')
    
    # Render HTML template with report data
    html_string = render_to_string('reports/report_pdf.html', {'report': report, 'content': report.content_json})
    
    # Generate PDF
    html = HTML(string=html_string, base_url=request.build_absolute_uri('/'))
    pdf = html.write_pdf()
    
    # Create HTTP response with PDF
    response = HttpResponse(pdf, content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="report_{report.id}.pdf"'
    
    return response

@login_required
def export_report_csv(request, pk):
    """Export report as CSV"""
    report = get_object_or_404(Report, pk=pk)
    
    # Check if user has permission
    if not request.user.is_superuser and report.created_by != request.user:
        messages.error(request, "You don't have permission to export this report.")
        return redirect('reports:report_list')
    
    # Create CSV file
    output = io.StringIO()
    writer = csv.writer(output)
    
    content = report.content_json
    
    # Write headers
    if report.report_type == Report.ReportType.NETWORK:
        writer.writerow(['Network Name', 'IP Range', 'Server Count', 'Domain Count', 'Critical Vulns', 'High Vulns', 'Medium Vulns', 'Low Vulns'])
        writer.writerow([
            content['network_name'],
            content['ip_range'],
            content['server_count'],
            content['domain_count'],
            content['vulnerabilities']['critical'],
            content['vulnerabilities']['high'],
            content['vulnerabilities']['medium'],
            content['vulnerabilities']['low']
        ])
        
        # Write server details
        writer.writerow([])
        writer.writerow(['Server Name', 'IP Address', 'OS', 'CPU Cores', 'RAM (GB)', 'Disk Space (GB)'])
        for server in content['servers']:
            writer.writerow([
                server['name'],
                server['ip_address'],
                server['operating_system'],
                server['cpu_cores'],
                server['ram_gb'],
                server['disk_space_gb']
            ])
    
    elif report.report_type == Report.ReportType.SERVER:
        writer.writerow(['Server Name', 'IP Address', 'OS', 'CPU Cores', 'RAM (GB)', 'Disk Space (GB)'])
        writer.writerow([
            content['server_name'],
            content['ip_address'],
            content['operating_system'],
            content['cpu_cores'],
            content['ram_gb'],
            content['disk_space_gb']
        ])
        
        # Write open ports
        writer.writerow([])
        writer.writerow(['Open Ports'])
        writer.writerow(['Port', 'Protocol', 'Service'])
        for port in content['open_ports']:
            writer.writerow([
                port['port_number'],
                port['protocol'],
                port['service']
            ])
        
        # Write vulnerabilities
        writer.writerow([])
        writer.writerow(['Vulnerabilities'])
        writer.writerow(['Title', 'Severity', 'CVE ID', 'Status'])
        for vuln in content['vulnerabilities']:
            writer.writerow([
                vuln['title'],
                vuln['severity'],
                vuln['cve_id'],
                'Fixed' if vuln['is_fixed'] else 'Open'
            ])
    
    elif report.report_type == Report.ReportType.DOMAIN:
        writer.writerow(['Domain Name', 'Server', 'Registrar', 'Registration Date', 'Expiration Date'])
        writer.writerow([
            content['domain_name'],
            content['server_name'],
            content['registrar'],
            content['registration_date'],
            content['expiration_date']
        ])
        
        # Write SSL certificates
        writer.writerow([])
        writer.writerow(['SSL Certificates'])
        writer.writerow(['Issuer', 'Valid From', 'Valid Until', 'Is Valid', 'Days Until Expiry'])
        for cert in content['ssl_certificates']:
            writer.writerow([
                cert['issuer'],
                cert['valid_from'],
                cert['valid_until'],
                'Yes' if cert['is_valid'] else 'No',
                cert['days_until_expiry']
            ])
    
    # Create response
    response = HttpResponse(output.getvalue(), content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="report_{report.id}.csv"'
    
    return response

