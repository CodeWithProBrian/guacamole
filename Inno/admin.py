from django.contrib import admin
from . import models

class CustomUserAdmin(admin.ModelAdmin):
    list_display = ('id', 'email', 'first_name', 'last_name', 'is_staff', 'is_superuser')
    search_fields = ('email', 'first_name', 'last_name')
    
class PendingUserAdmin(admin.ModelAdmin):
    list_display = ('id', 'email', 'first_name', 'last_name', 'phone')
    search_fields = ('email', 'first_name', 'last_name')
    
class PackageAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'price')
# Register your models here.
admin.site.register(models.Service)
admin.site.register(models.ServiceCategory)
admin.site.register(models.ServiceSection)
admin.site.register(models.Testimonial)
admin.site.register(models.CustomUser, CustomUserAdmin)
admin.site.register(models.PendingUser, PendingUserAdmin)
admin.site.register(models.Package, PackageAdmin)
admin.site.register(models.Transaction)
admin.site.register(models.UserProfile)