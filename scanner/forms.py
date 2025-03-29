from django import forms
from .models import (
    Network, Server, Domain, Application, 
    Person, PortScan, Vulnerability
)

class NetworkForm(forms.ModelForm):
    class Meta:
        model = Network
        fields = ['name', 'description', 'ip_range']
        widgets = {
            'description': forms.Textarea(attrs={'rows': 3}),
        }

class ServerForm(forms.ModelForm):
    class Meta:
        model = Server
        fields = [
            'name', 'hostname', 'ip_address', 'network', 
            'operating_system', 'os_version', 'cpu_cores', 
            'ram_gb', 'disk_space_gb', 'legal_representative', 
            'technical_representative'
        ]
        
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Make some fields optional in the form
        self.fields['hostname'].required = False
        self.fields['operating_system'].required = False
        self.fields['os_version'].required = False
        self.fields['cpu_cores'].required = False
        self.fields['ram_gb'].required = False
        self.fields['disk_space_gb'].required = False
        self.fields['legal_representative'].required = False
        self.fields['technical_representative'].required = False

class DomainForm(forms.ModelForm):
    class Meta:
        model = Domain
        fields = [
            'name', 'server', 'technical_representative', 
            'registrar', 'registration_date', 'expiration_date',
            'notes'
        ]
        widgets = {
            'registration_date': forms.DateInput(attrs={'type': 'date'}),
            'expiration_date': forms.DateInput(attrs={'type': 'date'}),
            'notes': forms.Textarea(attrs={'rows': 3}),
        }
        
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Make some fields optional in the form
        self.fields['server'].required = False
        self.fields['technical_representative'].required = False
        self.fields['registrar'].required = False
        self.fields['registration_date'].required = False
        self.fields['expiration_date'].required = False
        self.fields['notes'].required = False

class ApplicationForm(forms.ModelForm):
    class Meta:
        model = Application
        fields = [
            'name', 'server', 'domain', 'technology_type', 
            'version', 'description', 'installation_path', 
            'technical_representative'
        ]
        widgets = {
            'description': forms.Textarea(attrs={'rows': 3}),
        }
        
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Make some fields optional in the form
        self.fields['domain'].required = False
        self.fields['version'].required = False
        self.fields['description'].required = False
        self.fields['installation_path'].required = False
        self.fields['technical_representative'].required = False

class PersonForm(forms.ModelForm):
    class Meta:
        model = Person
        fields = ['name', 'email', 'phone', 'position', 'company']
        
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Make some fields optional in the form
        self.fields['phone'].required = False
        self.fields['position'].required = False
        self.fields['company'].required = False

class PortScanForm(forms.Form):
    port_range = forms.CharField(
        max_length=100,
        initial='1-1024',
        help_text='Enter a single port (e.g., 80), a range (e.g., 1-1024), or a comma-separated list (e.g., 22,80,443)'
    )

class VulnerabilityForm(forms.ModelForm):
    class Meta:
        model = Vulnerability
        fields = [
            'server', 'application', 'title', 'description', 
            'severity', 'cve_id', 'is_fixed'
        ]
        widgets = {
            'description': forms.Textarea(attrs={'rows': 4}),
        }
        
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Make some fields optional in the form
        self.fields['application'].required = False
        self.fields['cve_id'].required = False

