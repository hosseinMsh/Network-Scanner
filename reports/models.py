from django.db import models
from django.contrib.auth.models import User
from scanner.models import Network, Server, Domain

class Report(models.Model):
    """Model for representing a report"""
    class ReportType(models.TextChoices):
        NETWORK = 'network', 'Network Report'
        SERVER = 'server', 'Server Report'
        DOMAIN = 'domain', 'Domain Report'
        VULNERABILITY = 'vulnerability', 'Vulnerability Report'
        COMPREHENSIVE = 'comprehensive', 'Comprehensive Report'
    
    title = models.CharField(max_length=255)
    report_type = models.CharField(
        max_length=20,
        choices=ReportType.choices,
        default=ReportType.COMPREHENSIVE
    )
    network = models.ForeignKey(Network, on_delete=models.SET_NULL, null=True, blank=True, related_name='reports')
    server = models.ForeignKey(Server, on_delete=models.SET_NULL, null=True, blank=True, related_name='reports')
    domain = models.ForeignKey(Domain, on_delete=models.SET_NULL, null=True, blank=True, related_name='reports')
    
    description = models.TextField(blank=True, null=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='reports')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # Report content can be stored as JSON or in a file
    content_json = models.JSONField(blank=True, null=True)
    report_file = models.FileField(upload_to='reports/', blank=True, null=True)
    
    def __str__(self):
        return self.title

