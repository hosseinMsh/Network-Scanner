from django.contrib import admin
from .models import (
    Network, Server, Domain, Application, 
    SSLCertificate, PortScan, PortScanResult, 
    Vulnerability, Person
)

@admin.register(Network)
class NetworkAdmin(admin.ModelAdmin):
    list_display = ('name', 'ip_range', 'created_by', 'created_at')
    search_fields = ('name', 'ip_range')
    list_filter = ('created_at',)

@admin.register(Server)
class ServerAdmin(admin.ModelAdmin):
    list_display = ('name', 'ip_address', 'network', 'operating_system', 'created_by', 'created_at')
    search_fields = ('name', 'ip_address', 'hostname')
    list_filter = ('network', 'operating_system', 'created_at')

@admin.register(Domain)
class DomainAdmin(admin.ModelAdmin):
    list_display = ('name', 'server', 'registrar', 'registration_date', 'expiration_date')
    search_fields = ('name', 'registrar')
    list_filter = ('server', 'registration_date', 'expiration_date')

@admin.register(Application)
class ApplicationAdmin(admin.ModelAdmin):
    list_display = ('name', 'server', 'domain', 'technology_type', 'version')
    search_fields = ('name', 'version')
    list_filter = ('technology_type', 'server')

@admin.register(SSLCertificate)
class SSLCertificateAdmin(admin.ModelAdmin):
    list_display = ('domain', 'issuer', 'valid_from', 'valid_until', 'is_valid')
    search_fields = ('domain__name', 'issuer')
    list_filter = ('is_valid', 'valid_until')

@admin.register(PortScan)
class PortScanAdmin(admin.ModelAdmin):
    list_display = ('server', 'scan_date', 'scan_type', 'port_range', 'created_by')
    search_fields = ('server__name', 'server__ip_address')
    list_filter = ('scan_date', 'scan_type')

@admin.register(PortScanResult)
class PortScanResultAdmin(admin.ModelAdmin):
    list_display = ('port_scan', 'port_number', 'protocol', 'status', 'service')
    search_fields = ('port_number', 'service')
    list_filter = ('status', 'protocol')

@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = ('title', 'server', 'application', 'severity', 'cve_id', 'is_fixed')
    search_fields = ('title', 'cve_id', 'description')
    list_filter = ('severity', 'is_fixed', 'discovered_date')

@admin.register(Person)
class PersonAdmin(admin.ModelAdmin):
    list_display = ('name', 'email', 'phone', 'position', 'company')
    search_fields = ('name', 'email', 'company')
    list_filter = ('position', 'company')

