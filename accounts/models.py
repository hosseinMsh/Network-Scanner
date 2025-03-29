from django.db import models
from django.contrib.auth.models import User

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    job_title = models.CharField(max_length=100, blank=True, null=True)
    department = models.CharField(max_length=100, blank=True, null=True)
    phone_number = models.CharField(max_length=20, blank=True, null=True)  # Changed from 'phone' to 'phone_number'
    profile_picture = models.ImageField(upload_to='profile_pics/', blank=True, null=True)  # Added profile_picture field
    
    def __str__(self):
        return self.user.username

