from django.urls import path
from . import views

app_name = 'scanner'

urlpatterns = [
    # Network URLs
    path('networks/', views.network_list, name='network_list'),
    path('networks/<int:pk>/', views.network_detail, name='network_detail'),
    path('networks/create/', views.network_create, name='network_create'),
    path('networks/<int:pk>/edit/', views.network_edit, name='network_edit'),
    
    # Server URLs
    path('servers/', views.server_list, name='server_list'),
    path('servers/<int:pk>/', views.server_detail, name='server_detail'),
    path('servers/create/', views.server_create, name='server_create'),
    path('servers/<int:pk>/edit/', views.server_edit, name='server_edit'),
    path('servers/<int:server_id>/scan-ports/', views.scan_ports, name='scan_ports'),
    
    # Domain URLs
    path('domains/', views.domain_list, name='domain_list'),
    path('domains/<int:pk>/', views.domain_detail, name='domain_detail'),
    path('domains/create/', views.domain_create, name='domain_create'),
    path('domains/<int:pk>/edit/', views.domain_edit, name='domain_edit'),
    path('domains/<int:domain_id>/check-ssl/', views.check_ssl, name='check_ssl'),
    path('domains/<int:domain_id>/scan/', views.scan_domain, name='scan_domain'),
    
    # Technology detection URLs
    path('domains/<int:domain_id>/detect-technologies/', views.detect_technologies, name='detect_technologies'),
    path('domains/<int:domain_id>/technology-detection-results/', views.technology_detection_results, name='technology_detection_results'),
    
    # Application URLs
    path('applications/', views.application_list, name='application_list'),
    path('applications/<int:pk>/', views.application_detail, name='application_detail'),
    path('applications/create/', views.application_create, name='application_create'),
    path('applications/<int:pk>/edit/', views.application_edit, name='application_edit'),
    
    # Vulnerability URLs
    path('vulnerabilities/', views.vulnerability_list, name='vulnerability_list'),
    path('vulnerabilities/<int:pk>/', views.vulnerability_detail, name='vulnerability_detail'),
    path('vulnerabilities/create/', views.vulnerability_create, name='vulnerability_create'),
    path('vulnerabilities/<int:pk>/edit/', views.vulnerability_edit, name='vulnerability_edit'),
    
    # Port scan results
    path('port-scan-results/<int:scan_id>/', views.port_scan_results, name='port_scan_results'),
    
    # Person URLs
    path('people/', views.person_list, name='person_list'),
    path('people/create/', views.person_create, name='person_create'),
    path('people/<int:pk>/edit/', views.person_edit, name='person_edit'),
]

