from django.contrib import admin
from . import models

# Register your models here.
admin.site.register(models.site)

def get_queryset(self):
        queryset=super(ThisisAdmin, self).get_queryset(request)
        if request.user.is_superuser:
            return queryset
        return queryset.filter(owner=request.user)
