from django.contrib import admin
from .models import Report

@admin.register(Report)
class ReportAdmin(admin.ModelAdmin):
    list_display = ('title', 'report_type', 'created_by', 'created_at')
    search_fields = ('title', 'description')
    list_filter = ('report_type', 'created_at')
    readonly_fields = ('content_json',)

