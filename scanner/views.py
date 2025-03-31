from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse
from django.urls import reverse
from .models import (
    Network, Server, Domain, Application, 
    SSLCertificate, PortScan, PortScanResult, Vulnerability, Person, DomainReport
)
from .services.port_scanner import scan_server_ports
from .services.ssl_checker import check_ssl_certificate, check_ssl_info, get_domain_info
from .services.domain_scanner import retrieve_ipv4_from_domain, retrieve_ipv6_from_domain, detect_technologies
from .forms import (
    NetworkForm, ServerForm, DomainForm, ApplicationForm,
    PortScanForm, PersonForm, VulnerabilityForm
)
from django.utils import timezone
import json
from .services.tech_detector import TechnologyDetector
from datetime import datetime

@login_required
def network_list(request):
    """View for listing networks"""
    networks = Network.objects.all()
    
    if request.user.is_superuser:
        # Superusers can see all networks
        pass
    else:
        # Regular users can only see networks they created
        networks = networks.filter(created_by=request.user)
    
    context = {
        'networks': networks
    }
    return render(request, 'scanner/network_list.html', context)

@login_required
def network_detail(request, pk):
    """View for network details"""
    network = get_object_or_404(Network, pk=pk)
    
    # Check if user has permission to view this network
    if not request.user.is_superuser and network.created_by != request.user:
        messages.error(request, "You don't have permission to view this network.")
        return redirect('scanner:network_list')
    
    servers = network.servers.all()
    
    context = {
        'network': network,
        'servers': servers
    }
    return render(request, 'scanner/network_detail.html', context)

@login_required
def network_create(request):
    """View for creating a network"""
    if request.method == 'POST':
        form = NetworkForm(request.POST)
        if form.is_valid():
            network = form.save(commit=False)
            network.created_by = request.user
            network.save()
            messages.success(request, f"Network '{network.name}' created successfully.")
            return redirect('scanner:network_detail', pk=network.pk)
    else:
        form = NetworkForm()
    
    context = {
        'form': form,
        'title': 'Create Network'
    }
    return render(request, 'scanner/network_form.html', context)

@login_required
def network_edit(request, pk):
    """View for editing a network"""
    network = get_object_or_404(Network, pk=pk)
    
    # Check if user has permission to edit this network
    if not request.user.is_superuser and network.created_by != request.user:
        messages.error(request, "You don't have permission to edit this network.")
        return redirect('scanner:network_list')
    
    if request.method == 'POST':
        form = NetworkForm(request.POST, instance=network)
        if form.is_valid():
            form.save()
            messages.success(request, f"Network '{network.name}' updated successfully.")
            return redirect('scanner:network_detail', pk=network.pk)
    else:
        form = NetworkForm(instance=network)
    
    context = {
        'form': form,
        'title': f'Edit Network: {network.name}'
    }
    return render(request, 'scanner/network_form.html', context)

@login_required
def server_list(request):
    """View for listing servers"""
    if request.user.is_superuser:
        servers = Server.objects.all()
    else:
        servers = Server.objects.filter(created_by=request.user)
    
    context = {
        'servers': servers
    }
    return render(request, 'scanner/server_list_modern.html', context)

@login_required
def server_detail(request, pk):
    """View for server details"""
    server = get_object_or_404(Server, pk=pk)
    
    # Check if user has permission to view this server
    if not request.user.is_superuser and server.created_by != request.user:
        messages.error(request, "You don't have permission to view this server.")
        return redirect('scanner:server_list')
    
    domains = server.domains.all()
    applications = server.applications.all()
    port_scans = server.port_scans.order_by('-scan_date')[:5]
    vulnerabilities = server.vulnerabilities.all()
    
    context = {
        'server': server,
        'domains': domains,
        'applications': applications,
        'port_scans': port_scans,
        'vulnerabilities': vulnerabilities
    }
    return render(request, 'scanner/server_detail_modern.html', context)

@login_required
def server_create(request):
    """View for creating a server"""
    if request.method == 'POST':
        form = ServerForm(request.POST)
        if form.is_valid():
            server = form.save(commit=False)
            server.created_by = request.user
            server.save()
            messages.success(request, f"Server '{server.name}' created successfully.")
            return redirect('scanner:server_detail', pk=server.pk)
    else:
        # Pre-fill network if provided in query params
        network_id = request.GET.get('network')
        initial_data = {}
        if network_id:
            try:
                network = Network.objects.get(pk=network_id)
                initial_data['network'] = network
            except Network.DoesNotExist:
                pass
        
        form = ServerForm(initial=initial_data)
    
    context = {
        'form': form,
        'title': 'Create Server'
    }
    return render(request, 'scanner/server_form_modern.html', context)

@login_required
def server_edit(request, pk):
    """View for editing a server"""
    server = get_object_or_404(Server, pk=pk)
    
    # Check if user has permission to edit this server
    if not request.user.is_superuser and server.created_by != request.user:
        messages.error(request, "You don't have permission to edit this server.")
        return redirect('scanner:server_list')
    
    if request.method == 'POST':
        form = ServerForm(request.POST, instance=server)
        if form.is_valid():
            form.save()
            messages.success(request, f"Server '{server.name}' updated successfully.")
            return redirect('scanner:server_detail', pk=server.pk)
    else:
        form = ServerForm(instance=server)
    
    context = {
        'form': form,
        'title': f'Edit Server: {server.name}',
        'server': server
    }
    return render(request, 'scanner/server_form_modern.html', context)

@login_required
def domain_list(request):
    """View for listing domains"""
    if request.user.is_superuser:
        domains = Domain.objects.all()
    else:
        domains = Domain.objects.filter(server__created_by=request.user)
    
    # Get all servers for the filter dropdown
    if request.user.is_superuser:
        servers = Server.objects.all()
    else:
        servers = Server.objects.filter(created_by=request.user)
    
    context = {
        'domains': domains,
        'servers': servers
    }
    return render(request, 'scanner/domain_list_modern.html', context)

@login_required
def domain_detail(request, pk):
    """View for domain details"""
    domain = get_object_or_404(Domain, pk=pk)
    
    # Check if user has permission to view this domain
    if not request.user.is_superuser and domain.server.created_by != request.user:
        messages.error(request, "You don't have permission to view this domain.")
        return redirect('scanner:domain_list')
    
    applications = domain.applications.all()
    ssl_certificates = domain.ssl_certificates.all().order_by('-created_at')
    domain_reports = domain.domain_reports.all().order_by('-created_at')
    
    context = {
        'domain': domain,
        'applications': applications,
        'ssl_certificates': ssl_certificates,
        'domain_reports': domain_reports
    }
    return render(request, 'scanner/domain_detail_modern.html', context)
@login_required
def domain_report_view(request, domain_id):
    """View for displaying the domain report"""
    domain = get_object_or_404(Domain, pk=domain_id)
    domain_reports = domain.domain_reports.all()  # Assuming you have a related name for domain reports

    context = {
        'domain': domain,
        'domain_reports': domain_reports
    }
    return render(request, 'scanner/domain_report.html', context)  # Ensure the template exists


@login_required
def domain_edit(request, pk):
    """View for editing a domain"""
    domain = get_object_or_404(Domain, pk=pk)

    # Check if user has permission to edit this domain
    if not request.user.is_superuser and domain.server.created_by != request.user:
        messages.error(request, "You don't have permission to edit this domain.")
        return redirect('scanner:domain_list')

    if request.method == 'POST':
        form = DomainForm(request.POST, instance=domain)
        if form.is_valid():
            form.save()
            messages.success(request, f"Domain '{domain.name}' updated successfully.")
            return redirect('scanner:domain_detail', pk=domain.pk)
    else:
        form = DomainForm(instance=domain)

    context = {
        'form': form,
        'title': f'Edit Domain: {domain.name}',
        'domain': domain
    }
    return render(request, 'scanner/domain_form_modern.html', context)


@login_required
def domain_delete(request, pk):
    """View for deleting a domain"""
    domain = get_object_or_404(Domain, pk=pk)

    # Check if user has permission to delete this domain
    if not request.user.is_superuser and domain.server.created_by != request.user:
        messages.error(request, "You don't have permission to delete this domain.")
        return redirect('scanner:domain_list')

    if request.method == 'POST':
        domain.delete()
        messages.success(request, f"Domain '{domain.name}' deleted successfully.")
        return redirect('scanner:domain_list')

    context = {
        'domain': domain
    }
    return render(request, 'scanner/domain_confirm_delete.html', context)  # Ensure the template exists
@login_required
def detect_technologies(request, domain_id):
    """Detect technologies used by a domain"""
    domain = get_object_or_404(Domain, id=domain_id)

    if request.method == 'POST':
        # Perform technology detection
        detector = TechnologyDetector()
        tech_data = detector.detect_technologies(domain.name)

        # Save technology data to domain
        domain.tech_data = tech_data
        domain.last_scanned = timezone.now()
        domain.save()

        messages.success(request, f"Technology detection completed for {domain.name}")

        # Redirect to technology detection results page
        return redirect('scanner:technology_detection_results', domain_id=domain.id)

    return render(request, 'scanner/technology_detection.html', {
        'domain': domain,
    })
@login_required
def domain_create(request):
    """View for creating a domain"""
    if request.method == 'POST':
        form = DomainForm(request.POST)
        if form.is_valid():
            domain = form.save()
            messages.success(request, f"Domain '{domain.name}' created successfully.")
            return redirect('scanner:domain_detail', pk=domain.pk)
    else:
        # Pre-fill server if provided in query params
        server_id = request.GET.get('server')
        initial_data = {}
        if server_id:
            try:
                server = Server.objects.get(pk=server_id)
                initial_data['server'] = server
            except Server.DoesNotExist:
                pass
        
        form = DomainForm(initial=initial_data)
    
    context = {
        'form': form,
        'title': 'Create Domain'
    }
    return render(request, 'scanner/domain_form_modern.html', context)

@login_required
def domain_edit(request, pk):
    """View for editing a domain"""
    domain = get_object_or_404(Domain, pk=pk)
    
    # Check if user has permission to edit this domain
    if not request.user.is_superuser and domain.server.created_by != request.user:
        messages.error(request, "You don't have permission to edit this domain.")
        return redirect('scanner:domain_list')
    
    if request.method == 'POST':
        form = DomainForm(request.POST, instance=domain)
        if form.is_valid():
            form.save()
            messages.success(request, f"Domain '{domain.name}' updated successfully.")
            return redirect('scanner:domain_detail', pk=domain.pk)
    else:
        form = DomainForm(instance=domain)
    
    context = {
        'form': form,
        'title': f'Edit Domain: {domain.name}',
        'domain': domain
    }
    return render(request, 'scanner/domain_form_modern.html', context)

@login_required
def application_list(request):
    """View for listing applications"""
    if request.user.is_superuser:
        applications = Application.objects.all()
    else:
        applications = Application.objects.filter(server__created_by=request.user)
    
    context = {
        'applications': applications
    }
    return render(request, 'scanner/application_list.html', context)

@login_required
def application_detail(request, pk):
    """View for application details"""
    application = get_object_or_404(Application, pk=pk)
    
    # Check if user has permission to view this application
    if not request.user.is_superuser and application.server.created_by != request.user:
        messages.error(request, "You don't have permission to view this application.")
        return redirect('scanner:application_list')
    
    vulnerabilities = application.vulnerabilities.all()
    
    context = {
        'application': application,
        'vulnerabilities': vulnerabilities
    }
    return render(request, 'scanner/application_detail.html', context)

@login_required
def application_create(request):
    """View for creating an application"""
    if request.method == 'POST':
        form = ApplicationForm(request.POST)
        if form.is_valid():
            application = form.save()
            messages.success(request, f"Application '{application.name}' created successfully.")
            return redirect('scanner:application_detail', pk=application.pk)
    else:
        # Pre-fill server if provided in query params
        server_id = request.GET.get('server')
        domain_id = request.GET.get('domain')
        initial_data = {}
        
        if server_id:
            try:
                server = Server.objects.get(pk=server_id)
                initial_data['server'] = server
            except Server.DoesNotExist:
                pass
        
        if domain_id:
            try:
                domain = Domain.objects.get(pk=domain_id)
                initial_data['domain'] = domain
            except Domain.DoesNotExist:
                pass
        
        form = ApplicationForm(initial=initial_data)
    
    context = {
        'form': form,
        'title': 'Create Application'
    }
    return render(request, 'scanner/application_form.html', context)

@login_required
def application_edit(request, pk):
    """View for editing an application"""
    application = get_object_or_404(Application, pk=pk)
    
    # Check if user has permission to edit this application
    if not request.user.is_superuser and application.server.created_by != request.user:
        messages.error(request, "You don't have permission to view this application.")
        return redirect('scanner:application_list')
    
    if request.method == 'POST':
        form = ApplicationForm(request.POST, instance=application)
        if form.is_valid():
            form.save()
            messages.success(request, f"Application '{application.name}' updated successfully.")
            return redirect('scanner:application_detail', pk=application.pk)
    else:
        form = ApplicationForm(instance=application)
    
    context = {
        'form': form,
        'title': f'Edit Application: {application.name}'
    }
    return render(request, 'scanner/application_form.html', context)

@login_required
def vulnerability_list(request):
    """View for listing vulnerabilities"""
    if request.user.is_superuser:
        vulnerabilities = Vulnerability.objects.all()
    else:
        vulnerabilities = Vulnerability.objects.filter(server__created_by=request.user)
    
    context = {
        'vulnerabilities': vulnerabilities
    }
    return render(request, 'scanner/vulnerability_list.html', context)

@login_required
def vulnerability_detail(request, pk):
    """View for vulnerability details"""
    vulnerability = get_object_or_404(Vulnerability, pk=pk)
    
    # Check if user has permission to view this vulnerability
    if not request.user.is_superuser and vulnerability.server.created_by != request.user:
        messages.error(request, "You don't have permission to view this vulnerability.")
        return redirect('scanner:vulnerability_list')
    
    context = {
        'vulnerability': vulnerability
    }
    return render(request, 'scanner/vulnerability_detail.html', context)

@login_required
def vulnerability_create(request):
    """View for creating a vulnerability"""
    if request.method == 'POST':
        form = VulnerabilityForm(request.POST)
        if form.is_valid():
            vulnerability = form.save()
            messages.success(request, f"Vulnerability '{vulnerability.title}' created successfully.")
            return redirect('scanner:vulnerability_detail', pk=vulnerability.pk)
    else:
        # Pre-fill server and application if provided in query params
        server_id = request.GET.get('server')
        application_id = request.GET.get('application')
        initial_data = {}
        
        if server_id:
            try:
                server = Server.objects.get(pk=server_id)
                initial_data['server'] = server
            except Server.DoesNotExist:
                pass
        
        if application_id:
            try:
                application = Application.objects.get(pk=application_id)
                initial_data['application'] = application
            except Application.DoesNotExist:
                pass
        
        form = VulnerabilityForm(initial=initial_data)
    
    context = {
        'form': form,
        'title': 'Create Vulnerability'
    }
    return render(request, 'scanner/vulnerability_form.html', context)

@login_required
def vulnerability_edit(request, pk):
    """View for editing a vulnerability"""
    vulnerability = get_object_or_404(Vulnerability, pk=pk)
    
    # Check if user has permission to edit this vulnerability
    if not request.user.is_superuser and vulnerability.server.created_by != request.user:
        messages.error(request, "You don't have permission to view this vulnerability.")
        return redirect('scanner:vulnerability_list')
    
    if request.method == 'POST':
        form = VulnerabilityForm(request.POST, instance=vulnerability)
        if form.is_valid():
            form.save()
            messages.success(request, f"Vulnerability '{vulnerability.title}' updated successfully.")
            return redirect('scanner:vulnerability_detail', pk=vulnerability.pk)
    else:
        form = VulnerabilityForm(instance=vulnerability)
    
    context = {
        'form': form,
        'title': f'Edit Vulnerability: {vulnerability.title}'
    }
    return render(request, 'scanner/vulnerability_form.html', context)

@login_required
def scan_ports(request, server_id):
    """View for scanning ports on a server"""
    server = get_object_or_404(Server, pk=server_id)
    
    # Check if user has permission to scan this server
    if not request.user.is_superuser and server.created_by != request.user:
        messages.error(request, "You don't have permission to scan this server.")
        return redirect('scanner:server_list')
    
    if request.method == 'POST':
        form = PortScanForm(request.POST)
        if form.is_valid():
            port_range = form.cleaned_data['port_range']
            
            # Perform port scan
            port_scan = scan_server_ports(
                server_id=server.id,
                port_range=port_range,
                user_id=request.user.id
            )
            
            if port_scan:
                messages.success(request, f"Port scan completed for {server.name}.")
                return redirect('scanner:port_scan_results', scan_id=port_scan.id)
            else:
                messages.error(request, "Failed to perform port scan.")
        else:
            messages.error(request, "Invalid form data.")
    else:
        form = PortScanForm(initial={'port_range': '1-1024'})
    
    context = {
        'server': server,
        'form': form
    }
    return render(request, 'scanner/scan_ports.html', context)

@login_required
def port_scan_results(request, scan_id):
    """View for displaying port scan results"""
    port_scan = get_object_or_404(PortScan, pk=scan_id)
    
    # Check if user has permission to view these results
    if not request.user.is_superuser and port_scan.created_by != request.user:
        messages.error(request, "You don't have permission to view these results.")
        return redirect('scanner:server_list')
    
    results = port_scan.results.all()
    open_ports = results.filter(status='open')
    
    context = {
        'port_scan': port_scan,
        'results': results,
        'open_ports': open_ports
    }
    return render(request, 'scanner/port_scan_results.html', context)

@login_required
def check_ssl(request, domain_id):
    """View for checking SSL certificate for a domain"""
    domain = get_object_or_404(Domain, pk=domain_id)
    
    # Check if user has permission
    if not request.user.is_superuser and domain.server.created_by != request.user:
        messages.error(request, "You don't have permission to check SSL for this domain.")
        return redirect('scanner:domain_list')
    
    # Check SSL info
    ssl_info = check_ssl_info(domain.name)
    
    if ssl_info['has_ssl']:
        # Create or update SSL certificate
        ssl_cert, created = SSLCertificate.objects.update_or_create(
            domain=domain,
            defaults={
                'issuer': ssl_info['issuer'],
                'valid_from': ssl_info['valid_from'],
                'valid_until': ssl_info['ssl_expires_date'],
                'is_valid': True
            }
        )
        
        # Create domain report
        ipv4 = retrieve_ipv4_from_domain(domain.name)
        ipv6 = retrieve_ipv6_from_domain(domain.name)
        technologies = detect_technologies(domain.name)
        
        DomainReport.objects.create(
            domain=domain,
            has_ssl=ssl_info['has_ssl'],
            ssl_expires_date=ssl_info['ssl_expires_date'],
            ipv4_address=ipv4,
            ipv6_address=ipv6,
            technologies=technologies
        )
        
        messages.success(request, f"SSL certificate checked for {domain.name}.")
    else:
        messages.warning(request, f"No SSL certificate found for {domain.name}.")
    
    return redirect('scanner:domain_detail', pk=domain.id)

@login_required
def detect_technologies(request, domain_id):
    """Detect technologies used by a domain"""
    domain = get_object_or_404(Domain, id=domain_id)
    
    if request.method == 'POST':
        # Perform technology detection
        detector = TechnologyDetector()
        tech_data = detector.detect_technologies(domain.name)
        
        # Save technology data to domain
        domain.tech_data = tech_data
        domain.last_scanned = timezone.now()
        domain.save()
        
        messages.success(request, f"Technology detection completed for {domain.name}")
        
        # Redirect to technology detection results page
        return redirect('scanner:technology_detection_results', domain_id=domain.id)
    
    return render(request, 'scanner/technology_detection.html', {
        'domain': domain,
    })

@login_required
def technology_detection_results(request, domain_id):
    """Display technology detection results"""
    domain = get_object_or_404(Domain, id=domain_id)
    
    if not domain.tech_data:
        messages.warning(request, f"No technology data available for {domain.name}")
        return redirect('scanner:detect_technologies', domain_id=domain.id)
    
    return render(request, 'scanner/technology_detection_results.html', {
        'domain': domain,
        'tech_data': domain.tech_data,
    })

@login_required
def scan_domain(request, domain_id):
    """View for scanning a domain"""
    domain = get_object_or_404(Domain, pk=domain_id)
    
    # Check if user has permission
    if not request.user.is_superuser and domain.server.created_by != request.user:
        messages.error(request, "You don't have permission to scan this domain.")
        return redirect('scanner:domain_list')
    
    # Get domain info
    domain_info = get_domain_info(domain.name)
    
    # Update domain with whois info
    if domain_info['registrar']:
        domain.registrar = domain_info['registrar']
    
    if domain_info['creation_date']:
        if isinstance(domain_info['creation_date'], list):
            domain.registration_date = domain_info['creation_date'][0]
        else:
            domain.registration_date = domain_info['creation_date']
    
    if domain_info['expiration_date']:
        if isinstance(domain_info['expiration_date'], list):
            domain.expiration_date = domain_info['expiration_date'][0]
        else:
            domain.expiration_date = domain_info['expiration_date']
    
    domain.save()
    
    # Check SSL
    ssl_info = check_ssl_info(domain.name)
    
    if ssl_info['has_ssl']:
        # Create or update SSL certificate
        ssl_cert, created = SSLCertificate.objects.update_or_create(
            domain=domain,
            defaults={
                'issuer': ssl_info['issuer'],
                'valid_from': ssl_info['valid_from'],
                'valid_until': ssl_info['ssl_expires_date'],
                'is_valid': True
            }
        )

    # Get IP addresses
    ipv4 = retrieve_ipv4_from_domain(domain.name)
    ipv6 = retrieve_ipv6_from_domain(domain.name)
    
    # Detect technologies
    technologies = detect_technologies(domain.name)

    # Create domain report
    DomainReport.objects.create(
        domain=domain,
        has_ssl=ssl_info['has_ssl'],
        ssl_expires_date=ssl_info['ssl_expires_date'] if ssl_info['has_ssl'] else None,
        ipv4_address=ipv4,
        ipv6_address=ipv6,
        technologies=technologies
    )
    
    # Create applications based on detected technologies
    for tech in technologies['detected_apps']:
        tech_type = 'other'
        if tech.lower() in [choice[0] for choice in Application.TechnologyType.choices]:
            tech_type = tech.lower()
        
        Application.objects.update_or_create(
            server=domain.server,
            domain=domain,
            name=f"{tech} on {domain.name}",
            defaults={
                'technology_type': tech_type,
                'description': f"Detected {tech} on {domain.name}"
            }
        )
    
    messages.success(request, f"Domain {domain.name} scanned successfully.")
    return redirect('scanner:domain_detail', pk=domain.id)

@login_required
def person_list(request):
    """View for listing people (representatives)"""
    people = Person.objects.all()
    
    context = {
        'people': people
    }
    return render(request, 'scanner/person_list.html', context)

@login_required
def person_create(request):
    """View for creating a person"""
    if request.method == 'POST':
        form = PersonForm(request.POST)
        if form.is_valid():
            person = form.save()
            messages.success(request, f"Person '{person.name}' created successfully.")
            return redirect('scanner:person_list')
    else:
        form = PersonForm()
    
    context = {
        'form': form,
        'title': 'Create Person'
    }
    return render(request, 'scanner/person_form.html', context)

@login_required
def person_edit(request, pk):
    """View for editing a person"""
    person = get_object_or_404(Person, pk=pk)
    
    if request.method == 'POST':
        form = PersonForm(request.POST, instance=person)
        if form.is_valid():
            form.save()
            messages.success(request, f"Person '{person.name}' updated successfully.")
            return redirect('scanner:person_list')
    else:
        form = PersonForm(instance=person)
    
    context = {
        'form': form,
        'title': f'Edit Person: {person.name}'
    }
    return render(request, 'scanner/person_form.html', context)

