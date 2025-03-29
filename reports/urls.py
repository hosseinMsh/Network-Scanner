from django.urls import path
from . import views

app_name = 'reports'

urlpatterns = [
    path('', views.report_list, name='report_list'),
    path('<int:pk>/', views.report_detail, name='report_detail'),
    path('network/<int:network_id>/generate/', views.generate_network_report, name='generate_network_report'),
    path('server/<int:server_id>/generate/', views.generate_server_report, name='generate_server_report'),
    path('domain/<int:domain_id>/generate/', views.generate_domain_report, name='generate_domain_report'),
    path('<int:pk>/export/pdf/', views.export_report_pdf, name='export_report_pdf'),
    path('<int:pk>/export/csv/', views.export_report_csv, name='export_report_csv'),
]

