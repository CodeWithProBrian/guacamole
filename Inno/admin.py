from django.contrib import admin
from . import models
# Register your models here.
admin.site.register(models.Service)
admin.site.register(models.ServiceCategory)
admin.site.register(models.ServiceSection)
admin.site.register(models.Testimonial)