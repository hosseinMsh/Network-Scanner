from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.models import User
from .models import UserProfile

class UserProfileInline(admin.StackedInline):
    model = UserProfile
    can_delete = False
    verbose_name_plural = 'profile'

class UserAdmin(BaseUserAdmin):
    inlines = (UserProfileInline,)
    list_display = ('username', 'email', 'first_name', 'last_name', 'is_staff', 'get_job_title')
    
    def get_job_title(self, obj):
        try:
            return obj.profile.job_title
        except UserProfile.DoesNotExist:
            return ''
    get_job_title.short_description = 'Job Title'

# Re-register UserAdmin
admin.site.unregister(User)
admin.site.register(User, UserAdmin)

