from django.shortcuts import render
from . import models
# Create your views here.
def home(request):
    services = models.Service.objects.filter(is_active=True)
    service_section = models.ServiceSection.objects.filter(is_active=True).first()
    testimonials = models.Testimonial.objects.filter(is_active=True).order_by('-created_at')
    context = {
        'services': services,
        'service_section': service_section,
        'testimonials': testimonials,
    }
    return render(request, 'home.html', context)