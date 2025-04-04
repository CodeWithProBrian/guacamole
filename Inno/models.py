from django.db import models
from django.utils import timezone
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.contrib.auth import get_user_model
import secrets
import datetime
from django.utils import timezone
from django.core.validators import RegexValidator
from datetime import timedelta
# Create your models here.
class CustomUserManager(BaseUserManager):
    def _create_user(self, email, password, **extra_fields):
        if not email:
            raise ValueError("Email must be provided")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user
    
    def create_user(self, email, password, **extra_fields):
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)
        return self._create_user(email, password, **extra_fields)
    
    def create_superuser(self, email, password, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self._create_user(email, password, **extra_fields)

class CustomUser(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True, verbose_name="email address")
    first_name = models.CharField(max_length=50, blank=True)
    last_name = models.CharField(max_length=50, blank=True)
    profile = models.ImageField(blank=True, upload_to='profile')
    phone = models.CharField(max_length=50, blank=True)
    is_staff = models.BooleanField(default=False, help_text="Designates whether the user is a staff member")
    is_active = models.BooleanField(default=True, help_text="Designates whether the user is active in the system")
    date_joined = models.DateTimeField(verbose_name="date joined", auto_now_add=True)
    last_login = models.DateTimeField(verbose_name="last login", auto_now_add=True)
    objects = CustomUserManager()
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []
    
    class Meta:
        verbose_name = "user"
        verbose_name_plural = "users"
    def __str__(self):
        return self.first_name + " " + self.last_name

class ContactSubmission(models.Model):
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    email = models.EmailField()
    subject = models.CharField(max_length=200)
    phone = models.CharField(max_length=20, blank=True, null=True)
    message = models.TextField()
    
    # Metadata
    created_at = models.DateTimeField(default=timezone.now)
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    is_read = models.BooleanField(default=False)
    
    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Contact Submission'
        verbose_name_plural = 'Contact Submissions'
    
    def __str__(self):
        return f"{self.name} - {self.subject} - {self.created_at.strftime('%Y-%m-%d')}"
# Create your models here.
class ServiceCategory(models.Model):
    name = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name
    
    class Meta:
        verbose_name_plural = "Service Categories"


class Service(models.Model):
    STYLE_CHOICES = (
        ('one', 'Style One'),
        ('two', 'Style Two'),
        ('three', 'Style Three'),
    )
    
    title = models.CharField(max_length=200)
    description = models.TextField()
    icon = models.CharField(max_length=50, help_text="Icon class name (e.g., 'lni lni-android')")
    style_class = models.CharField(max_length=20, choices=STYLE_CHOICES, default='one')
    category = models.ForeignKey(ServiceCategory, on_delete=models.SET_NULL, null=True, blank=True, related_name='services')
    learn_more_url = models.CharField(blank=True,max_length=300, null=True)
    is_active = models.BooleanField(default=True)
    order = models.PositiveIntegerField(default=0, help_text="Order of display")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.title
    
    class Meta:
        ordering = ['order']


class ServiceSection(models.Model):
    title = models.CharField(max_length=200)
    subtitle = models.CharField(max_length=200)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.title
    
    class Meta:
        verbose_name = "Service Section"
        verbose_name_plural = "Service Section"
        
class Testimonial(models.Model):
    name = models.CharField(max_length=100)
    position = models.CharField(max_length=100)
    testimonial = models.TextField()
    image = models.ImageField(upload_to='testimonials/')
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return self.name
class EmailVerificationToken(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    token = models.CharField(max_length=64, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()

    def save(self, *args, **kwargs):
        if not self.token:
            self.token = secrets.token_urlsafe(32)
            self.expires_at = timezone.now() + timedelta(minutes=30)  # 30 minute expiration
        super().save(*args, **kwargs)

    def is_valid(self):
        return timezone.now() < self.expires_at

class PendingUser(models.Model):
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    phone = models.CharField(max_length=20)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=128)  # Store hashed password
    verification_token = models.CharField(max_length=64, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()

    def save(self, *args, **kwargs):
        if not self.verification_token:
            self.verification_token = secrets.token_urlsafe(32)
            self.expires_at = timezone.now() + timedelta(minutes=30)
        super().save(*args, **kwargs)

    def is_valid(self):
        return timezone.now() < self.expires_at
class PasswordResetToken(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    token = models.CharField(max_length=64, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()

    def save(self, *args, **kwargs):
        if not self.token:
            self.token = secrets.token_urlsafe(32)  # Generate a secure token
            self.expires_at = timezone.now() + datetime.timedelta(hours=1)  # Expires in 1 hour
        super().save(*args, **kwargs)

    def is_valid(self):
        return timezone.now() < self.expires_at

class Package(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=200)
    price = models.CharField(max_length=20, blank=True, null=True)
    ussd = models.CharField(max_length=300)
    validity = models.PositiveIntegerField(help_text="Validity in hours")
    retry = models.PositiveIntegerField(default=0)
    
    
    phone_regex = RegexValidator(
        regex=r'^\+?1?\d{9,15}$', 
        message="Phone number must be entered in the format: '+999999999'. Up to 15 digits allowed."
    )
    class Meta:
        ordering = ['id']
    
    def __str__(self):
        return f"{self.name} - Ksh. {self.price}"

class Transaction(models.Model):
    STATUS_CHOICES = (
        ('PENDING', 'Pending'),
        ('COMPLETED', 'Completed'),
        ('FAILED', 'Failed'),
    )
    paying_number = models.CharField(max_length=15)
    receiver_number = models.CharField(max_length=15)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    package = models.ForeignKey(Package, on_delete=models.CASCADE)
    reference = models.CharField(max_length=50, unique=True)
    checkout_request_id = models.CharField(max_length=100, blank=True, null=True)
    mpesa_receipt = models.CharField(max_length=50, blank=True, null=True)
    transaction_date = models.CharField(max_length=50, blank=True, null=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='PENDING')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.reference} - {self.amount} - {self.status}"