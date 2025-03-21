from django.shortcuts import redirect, render
from django.contrib import messages
from django.core.mail import send_mail
from django.conf import settings
from . import models
from dotenv import load_dotenv

load_dotenv()
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

def about(request):
    return render(request, 'about.html')

def contact(request):
    if request.method == 'POST':
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        email = request.POST.get('email')
        subject = request.POST.get('subject')
        phone = request.POST.get('phone')
        message = request.POST.get('message')
        
        
        
        if not first_name or not last_name or not email or not phone or not subject or not phone or not message:
            messages.error(request, 'All fields are required.')
            return redirect('contact')

        # Save the contact information to the database
        models.ContactSubmission.objects.create(
            first_name=first_name,
            last_name= last_name,
            email=email,
            subject=subject,
            phone=phone,
            message=message
        )

        # Send an email to the admin
        admin_email = settings.ADMIN_EMAIL  # Ensure this is set in your settings.py
        admin_subject = f"New Contact Form Submission: {subject}"
        admin_message = (
            f"You have received a new contact form submission:\n\n"
            f"Name: {first_name} {last_name}\n"
            f"Email: {email}\n"
            f"Phone: {phone}\n"
            f"Message: {message}\n"
        )

        send_mail(
            subject=admin_subject,
            message=admin_message,
            from_email=settings.DEFAULT_FROM_EMAIL,  # Ensure this is set in your settings.py
            recipient_list=[admin_email],
            fail_silently=False,
        )

        # Send a confirmation email to the user
        user_subject = "Thank You for Contacting Us"
        user_message = (
            f"Dear {first_name} {last_name},\n\n"
            f"Thank you for reaching out to us. We have received your message and will get back to you shortly.\n\n"
            f"Here are the details you submitted:\n"
            f"Name: {first_name} {last_name}\n"
            f"Email: {email}\n"
            f"Phone: {phone}\n"
            f"Message: {message}\n\n"
            f"Best regards,\n"
            f"{settings.SITE_NAME}\n"
            f"{settings.SITE_URL}"
        )

        send_mail(
            subject=user_subject,
            message=user_message,
            from_email=settings.DEFAULT_FROM_EMAIL,  # Ensure this is set in your settings.py
            recipient_list=[email],
            fail_silently=False,
        )
        return redirect('success')
    return render(request, 'contact.html')