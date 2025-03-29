from django.db import models
from django.contrib.auth.models import User
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from datetime import timedelta
from django.core.validators import RegexValidator

class Person(models.Model):
    """Model for representing a person (legal or technical representative)"""
    name = models.CharField(max_length=255)
    email = models.EmailField()
    phone = models.CharField(max_length=20, blank=True, null=True)
    position = models.CharField(max_length=100, blank=True, null=True)
    company = models.CharField(max_length=255, blank=True, null=True)
    
    def __str__(self):
        return self.name

class Network(models.Model):
    """Model for representing a network"""
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    ip_range = models.CharField(max_length=255, help_text="e.g., 192.168.1.0/24")
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='networks')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.name

class Server(models.Model):
    """Model for representing a server"""
    name = models.CharField(max_length=255)
    hostname = models.CharField(max_length=255, blank=True, null=True)
    ip_address = models.GenericIPAddressField()
    network = models.ForeignKey(Network, on_delete=models.CASCADE, related_name='servers')
    operating_system = models.CharField(max_length=100, blank=True, null=True)
    os_version = models.CharField(max_length=50, blank=True, null=True)
    
    # Server specifications
    cpu_cores = models.PositiveIntegerField(blank=True, null=True)
    ram_gb = models.PositiveIntegerField(blank=True, null=True)
    disk_space_gb = models.PositiveIntegerField(blank=True, null=True)
    gpu = models.CharField(max_length=100, blank=True, null=True)
    
    # Representatives
    legal_representative = models.ForeignKey(
        Person, on_delete=models.SET_NULL, null=True, blank=True, related_name='legal_servers'
    )
    technical_representative = models.ForeignKey(
        Person, on_delete=models.SET_NULL, null=True, blank=True, related_name='technical_servers'
    )
    
    # Metadata
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='servers')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_scanned = models.DateTimeField(blank=True, null=True)
    
    def __str__(self):
        return f"{self.name} ({self.ip_address})"

class Domain(models.Model):
    """Model for representing a domain"""
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('inactive', 'Inactive'),
        ('expiring', 'Expired Soon'),
        ('issues', 'With Issues'),
    ]
    
    name = models.CharField(
        max_length=255,
        validators=[
            RegexValidator(
                regex=r'^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$',
                message="Enter a valid domain (e.g., example.com)"
            )
        ]
    )
    server = models.ForeignKey(Server, on_delete=models.CASCADE, related_name='domains')
    technical_representative = models.ForeignKey(
        Person, on_delete=models.SET_NULL, null=True, blank=True, related_name='domains'
    )
    registrar = models.CharField(max_length=255, blank=True, null=True)
    registration_date = models.DateField(blank=True, null=True)
    expiration_date = models.DateField(blank=True, null=True)
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='active',
        verbose_name="Status"
    )
    notes = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_scanned = models.DateTimeField(blank=True, null=True)
    ssl_info = models.JSONField(blank=True, null=True)
    whois_info = models.JSONField(blank=True, null=True)
    dns_records = models.JSONField(blank=True, null=True)
    headers = models.JSONField(blank=True, null=True)
    tech_data = models.JSONField(blank=True, null=True)  # Added field for technology detection data
    
    def __str__(self):
        return self.name
    
    def check_expiry_status(self):
        """Update the status based on the expiry date."""
        if self.expiration_date:
            current_time = timezone.now().date()
            if self.expiration_date < current_time:
                self.status = 'inactive'
            elif self.expiration_date < current_time + timedelta(days=180):
                self.status = 'expiring'
            else:
                self.status = 'active'
    
    def save(self, *args, **kwargs):
        self.check_expiry_status()
        super().save(*args, **kwargs)

class Application(models.Model):
    """Model for representing an application installed on a server"""
    class TechnologyType(models.TextChoices):
        DJANGO = 'django', _('Django')
        FLASK = 'flask', _('Flask')
        LARAVEL = 'laravel', _('Laravel')
        NODEJS = 'nodejs', _('Node.js')
        REACT = 'react', _('React')
        ANGULAR = 'angular', _('Angular')
        WORDPRESS = 'wordpress', _('WordPress')
        OTHER = 'other', _('Other')
    
    name = models.CharField(max_length=255)
    server = models.ForeignKey(Server, on_delete=models.CASCADE, related_name='applications')
    domain = models.ForeignKey(Domain, on_delete=models.SET_NULL, null=True, blank=True, related_name='applications')
    technology_type = models.CharField(
        max_length=20,
        choices=TechnologyType.choices,
        default=TechnologyType.OTHER
    )
    version = models.CharField(max_length=50, blank=True, null=True)
    description = models.TextField(blank=True, null=True)
    installation_path = models.CharField(max_length=255, blank=True, null=True)
    technical_representative = models.ForeignKey(
        Person, on_delete=models.SET_NULL, null=True, blank=True, related_name='applications'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.name} ({self.technology_type})"

class SSLCertificate(models.Model):
    """Model for representing an SSL certificate"""
    domain = models.ForeignKey(Domain, on_delete=models.CASCADE, related_name='ssl_certificates')
    issuer = models.CharField(max_length=255)
    valid_from = models.DateTimeField()
    valid_until = models.DateTimeField()
    is_valid = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"SSL for {self.domain.name}"
    
    @property
    def days_until_expiry(self):
        from django.utils import timezone
        delta = self.valid_until - timezone.now()
        return delta.days

class PortScan(models.Model):
    """Model for representing a port scan"""
    server = models.ForeignKey(Server, on_delete=models.CASCADE, related_name='port_scans')
    scan_date = models.DateTimeField(auto_now_add=True)
    scan_type = models.CharField(max_length=50, default='TCP')
    port_range = models.CharField(max_length=100, default='1-1024')
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='port_scans')
    
    def __str__(self):
        return f"Port scan for {self.server.name} on {self.scan_date}"

class PortScanResult(models.Model):
    """Model for representing a port scan result"""
    port_scan = models.ForeignKey(PortScan, on_delete=models.CASCADE, related_name='results')
    port_number = models.PositiveIntegerField()
    protocol = models.CharField(max_length=10, default='TCP')
    status = models.CharField(max_length=20)  # open, closed, filtered
    service = models.CharField(max_length=100, blank=True, null=True)
    
    def __str__(self):
        return f"Port {self.port_number} ({self.status})"

class Vulnerability(models.Model):
    """Model for representing a vulnerability"""
    class Severity(models.TextChoices):
        CRITICAL = 'critical', _('Critical')
        HIGH = 'high', _('High')
        MEDIUM = 'medium', _('Medium')
        LOW = 'low', _('Low')
        INFO = 'info', _('Informational')
    
    server = models.ForeignKey(Server, on_delete=models.CASCADE, related_name='vulnerabilities')
    application = models.ForeignKey(
        Application, on_delete=models.SET_NULL, null=True, blank=True, related_name='vulnerabilities'
    )
    title = models.CharField(max_length=255)
    description = models.TextField()
    severity = models.CharField(
        max_length=10,
        choices=Severity.choices,
        default=Severity.MEDIUM
    )
    cve_id = models.CharField(max_length=50, blank=True, null=True)
    discovered_date = models.DateTimeField(auto_now_add=True)
    is_fixed = models.BooleanField(default=False)
    fixed_date = models.DateTimeField(blank=True, null=True)
    
    def __str__(self):
        return self.title

class DomainReport(models.Model):
    """Model for representing a domain report"""
    domain = models.ForeignKey(Domain, on_delete=models.CASCADE, related_name='domain_reports')
    has_ssl = models.BooleanField(default=False)
    ssl_expires_date = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    ipv4_address = models.GenericIPAddressField(null=True, blank=True)
    ipv6_address = models.GenericIPAddressField(null=True, blank=True)
    technologies = models.JSONField(null=True, blank=True)
    
    def __str__(self):
        return f"Report for {self.domain.name}"

