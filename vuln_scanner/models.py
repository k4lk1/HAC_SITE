from django.db import models
from django.utils import timezone
from django.urls import reverse
from django.contrib.auth.models import User
# Create your models here.

class site(models.Model):
    site_url=models.URLField()
    author=models.ForeignKey(User, on_delete=models.CASCADE, null=True)
    lfi_status=models.CharField(max_length=1000, blank=True, null=True)
    date_posted=models.DateTimeField(default=timezone.now)

    def __str__(self):
        return self.site_url
   

class reviews(models.Model):
    email_id=models.EmailField()
    feedback=models.TextField()
    
    def __str__(self):
        return self.email_id
