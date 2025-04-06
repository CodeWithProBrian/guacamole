import json
import uuid
from django.contrib.auth.views import LoginView
from django.core.exceptions import ValidationError
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.decorators.csrf import csrf_protect
from django.http import HttpResponseBadRequest, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.contrib import messages
from django.contrib.auth.hashers import make_password
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.template.loader import render_to_string
from django.contrib.auth.decorators import user_passes_test
from django.core.mail import send_mail
from django.conf import settings
from django.urls import reverse
from . import models
from .forms import PackageForm, ProfileUpdateForm, UserUpdateForm, ProfileUpdateForm, PasswordChangeCustomForm,DeactivateAccountForm
from django.contrib.auth import update_session_auth_hash
import os, logging
import requests
import base64, re
from datetime import datetime
from dotenv import load_dotenv
from django.contrib.auth.decorators import login_required
from django.contrib.auth import logout, login, authenticate
from django.contrib.auth.hashers import check_password
load_dotenv()

logger = logging.getLogger(__name__)
# Load environment variables
CONSUMER_KEY = os.getenv("CONSUMER_KEY")
CONSUMER_SECRET = os.getenv("CONSUMER_SECRET")
MPESA_PASSKEY = os.getenv("MPESA_PASSKEY")
MPESA_SHORTCODE = os.getenv("MPESA_SHORTCODE")
CALLBACK_URL = os.getenv("CALLBACK_URL")
MPESA_BASE_URL = os.getenv("MPESA_BASE_URL")
TILL_NUMBER = os.getenv("TILL_NUMBER")

def format_phone_number(phone):
    phone = phone.replace("+", "")
    if re.match(r"^254\d{9}$", phone):
        return phone
    elif phone.startswith("0") and len(phone) == 10:
        return "254" + phone[1:]
    else:
        raise ValueError("Invalid phone number format")

def get_access_token():
    try:
        credentials = f"{CONSUMER_KEY}:{CONSUMER_SECRET}"
        encoded_credentials = base64.b64encode(credentials.encode()).decode()

        headers = {
            "Authorization": f"Basic {encoded_credentials}",
            "Content-Type": "application/json",
        }
        response = requests.get(
            f"{MPESA_BASE_URL}/oauth/v1/generate?grant_type=client_credentials",
            headers=headers,
        ).json()

        if "access_token" in response:
            return response["access_token"]
        else:
            raise Exception("Access token missing in response.")
    except requests.RequestException as e:
        raise Exception(f"Failed to connect to M-Pesa: {str(e)}")

def initiate_stk_push(phone_number, amount, package_id):
    try:
        token = get_access_token()
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        stk_password = base64.b64encode(
            (MPESA_SHORTCODE + MPESA_PASSKEY + timestamp).encode()
        ).decode()

        request_body = {
            "BusinessShortCode": MPESA_SHORTCODE,
            "Password": stk_password,
            "Timestamp": timestamp,
            "TransactionType": "CustomerBuyGoodsOnline",
            "Amount": amount,
            "PartyA": phone_number,
            "PartyB": 9445283,
            "PhoneNumber": phone_number,
            "CallBackURL": CALLBACK_URL,
            "AccountReference": "INNOVESTRA TECH ENTERPRISES",
            "TransactionDesc": "Payment purchase of bingwa products",
        }

        response = requests.post(
            f"{MPESA_BASE_URL}/mpesa/stkpush/v1/processrequest",
            json=request_body,
            headers=headers,
        ).json()

        return response

    except Exception as e:
        print(f"Failed to initiate STK Push: {str(e)}")
        return e

def query_stk_push(checkout_id):
    print("Quering...")
    try:
        token = get_access_token()
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        password = base64.b64encode(
            (MPESA_SHORTCODE + MPESA_PASSKEY + timestamp).encode()
        ).decode()

        request_body = {
            "BusinessShortCode": MPESA_SHORTCODE,
            "Password": password,
            "Timestamp": timestamp,
            "CheckoutRequestID": checkout_id
        }

        response = requests.post(
            f"{MPESA_BASE_URL}/mpesa/stkpushquery/v1/query",
            json=request_body,
            headers=headers,
        )
        print(response.json())
        return response.json()

    except requests.RequestException as e:
        print(f"Error querying STK status: {str(e)}")
        return {"error": str(e)}

def initiate_payment(request):
    if request.method == 'POST':
        try:
            package_id = request.POST.get('package_id')
            amount = request.POST.get('amount')
            purchase_type = request.POST.get('purchase_type')
            
            if purchase_type == 'my_number':
                receiver_number = format_phone_number(request.POST.get('receiver_number'))
                payment_number = receiver_number  # Same number for receiving and payment
            else:  # other_number
                receiver_number = format_phone_number(request.POST.get('other_receiver_number'))
                payment_number = format_phone_number(request.POST.get('payment_number'))
 
            response = initiate_stk_push(
                phone_number=payment_number,
                amount=amount,
                package_id=package_id
            )
            
            if response and isinstance(response, dict) and response.get("ResponseCode") == "0":
                checkout_request_id = response.get("CheckoutRequestID")
                if not checkout_request_id:
                    messages.error(request, "Missing checkout request ID in response.")
                    return render(request, "bingwa.html")
                
                context = {"checkout_request_id": checkout_request_id}
                return render(request, "pending.html", context)
            else:
                # Get error message safely with a default if not present
                error_message = "Failed to send STK push. Please try again."
                if response and isinstance(response, dict) and "errorMessage" in response:
                    error_message = response["errorMessage"]
                
                messages.error(request, error_message)
                return render(request, "bingwa.html")
                
        except models.Package.DoesNotExist:
            messages.error(request, "Selected package does not exist.")
            return redirect('store')
        except ValueError as e:
            messages.error(request, str(e))
            return redirect('store')
        except Exception as e:
            import traceback
            print(traceback.format_exc())  # Detailed error in console
            messages.error(request, f"An unexpected error occurred: {str(e)}")
            return redirect('store')
    
    # Add this return statement for non-POST requests
    return render(request, "bingwa.html")  # or redirect to another page
# View to handle the STK status query
def query_stk_push(checkout_id):
    print("Quering...")
    try:
        token = get_access_token()
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        password = base64.b64encode(
            (MPESA_SHORTCODE + MPESA_PASSKEY + timestamp).encode()
        ).decode()

        request_body = {
            "BusinessShortCode": MPESA_SHORTCODE,
            "Password": password,
            "Timestamp": timestamp,
            "CheckoutRequestID": checkout_id
        }

        response = requests.post(
            f"{MPESA_BASE_URL}/mpesa/stkpushquery/v1/query",
            json=request_body,
            headers=headers,
        )
        print(response.json())
        return response.json()

    except requests.RequestException as e:
        print(f"Error querying STK status: {str(e)}")
        return {"error": str(e)}


# View to query the STK status and return it to the frontend
def stk_status_view(request):
    if request.method == 'POST':
        try:
            # Parse the JSON body
            data = json.loads(request.body)
            checkout_id = data.get('checkout_request_id')
            print("CheckoutRequestID:", checkout_id)

            # Query the STK push status using your backend function
            status = query_stk_push(checkout_id)

            # Return the status as a JSON response
            return JsonResponse({"status": status})
        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON body"}, status=400)
    return JsonResponse({"error": "Invalid request method"}, status=405)

 # To allow POST requests from external sources like M-Pesa
@csrf_exempt  # To allow POST requests from external sources like M-Pesa
def payment_callback(request):
    if request.method != "POST":
        return HttpResponseBadRequest("Only POST requests are allowed")

    try:
        callback_data = json.loads(request.body)  # Parse the request body
        result_code = callback_data["Body"]["stkCallback"]["ResultCode"]

        if result_code == 0:
            # Successful transaction
            checkout_id = callback_data["Body"]["stkCallback"]["CheckoutRequestID"]
            metadata = callback_data["Body"]["stkCallback"]["CallbackMetadata"]["Item"]

            amount = next(item["Value"] for item in metadata if item["Name"] == "Amount")
            mpesa_id = next(item["Value"] for item in metadata if item["Name"] == "MpesaReceiptNumber")
            payment_number = next(item["Value"] for item in metadata if item["Name"] == "PhoneNumber")
            transaction_date = next(item["Value"] for item in metadata if item["Name"] == "TransactionDate")

            # Save transaction to the database
            transaction = models.Transaction.objects.create(
                amount=amount, 
                checkout_id=checkout_id, 
                mpesa_id=mpesa_id, 
                phone_number=payment_number,
                transaction_date=transaction_date,  # Format the transaction date to a datetime object
                status="Success"
            )
            transaction.save()
            return JsonResponse({"ResultCode": 0, "ResultDesc": "Payment successful"})

        # Payment failed
        return JsonResponse({"ResultCode": result_code, "ResultDesc": "Payment failed"})

    except (json.JSONDecodeError, KeyError) as e:
        return HttpResponseBadRequest(f"Invalid request data: {str(e)}")


def home(request):
    
    testimonials = models.Testimonial.objects.filter(is_active=True).order_by('-created_at')
    context = {
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

def contact_success(request):
    return render(request, 'contact_success.html')

def UserRegister(request):
    if request.method == 'POST':
        first_name = request.POST['first_name']
        last_name = request.POST['last_name']
        phone = request.POST['phone']
        email = request.POST['email']
        password = request.POST['password']
        confirm_password = request.POST['password_confirm']
        
        # Validation checks
        if not all([first_name, last_name, phone, email, password, confirm_password]):
            messages.error(request, 'All fields are required.')
            return redirect('register')
        if password != confirm_password:
            messages.error(request, 'Passwords do not match.')
            return redirect('register')
        if models.CustomUser.objects.filter(email=email).exists():
            messages.error(request, 'Email already exists.')
            return redirect('register')
        if len(password) < 8:
            messages.error(request, 'Password must be at least 8 characters long.')
            return redirect('register')
            
        # Check if already pending verification
        if models.PendingUser.objects.filter(email=email).exists():
            pending_user = models.PendingUser.objects.get(email=email)
            if pending_user.is_valid():
                messages.info(request, 'Verification email already sent. Please check your inbox.')
                return redirect('register')
            else:
                pending_user.delete()  # Remove expired pending user

        # Store in PendingUser instead of creating actual user
        pending_user = models.PendingUser.objects.create(
            first_name=first_name,
            last_name=last_name,
            phone=phone,
            email=email,
            password=make_password(password)  # Store hashed password
        )
        
        # Build verification URL
        verification_url = request.build_absolute_uri(
            reverse('verify_email', kwargs={'token': pending_user.verification_token}))
        
        # Send verification email
        subject = "Verify Your Email Address"
        message = (
            f"Hi {first_name},\n\n"
            f"Please verify your email address by clicking the link below:\n\n"
            f"{verification_url}\n\n"
            f"This link will expire in 30 minutes.\n\n"
            f"If you didn't create an account, please ignore this email.\n\n"
            f"Thanks,\n"
            f"{settings.SITE_NAME}\n\n"
            f"{settings.SITE_URL}"
        )
        
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[email],
            fail_silently=False,
        )
        
        messages.success(request, 'Please check your email to complete registration.')
        return redirect('register')
    
    return render(request, 'signup.html')

def verify_email(request, token):
    try:
        pending_user = models.PendingUser.objects.get(verification_token=token)
        
        if not pending_user.is_valid():
            pending_user.delete()
            messages.error(request, 'Verification link has expired. Please register again.')
            return redirect('register')
        
        # Create the actual user WITHOUT hashing the password again
        user = models.CustomUser.objects.create(
            email=pending_user.email,
            password=pending_user.password,  # Already hashed, don't use create_user
            first_name=pending_user.first_name,
            last_name=pending_user.last_name,
            phone=pending_user.phone,
            is_active=True
        )
        
        # Delete the pending user record
        pending_user.delete()
        
        # Automatically log the user in after verification
        user.backend = 'django.contrib.auth.backends.ModelBackend'
        login(request, user)
        
        messages.success(request, 'Email verified successfully! You are now logged in.')
        return redirect('home')
    
    except models.PendingUser.DoesNotExist:
        messages.error(request, 'Invalid verification link. Please register again.')
        return redirect('register')
@require_POST
def resend_verification(request):
    try:
        import json
        data = json.loads(request.body)
        email = data.get('email')
        
        pending_user = models.PendingUser.objects.get(email=email)
        
        # Create new verification URL
        verification_url = request.build_absolute_uri(
            reverse('verify_email', kwargs={'token': pending_user.verification_token}))
        
        # Send verification email
        send_mail(
            subject="Verify Your Email Address",
            message=f"Please verify your email by clicking: {verification_url}",
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[email],
            fail_silently=False,
        )
        
        return JsonResponse({
            'success': True,
            'message': 'New verification email sent! Please check your inbox.'
        })
    
    except models.PendingUser.DoesNotExist:
        return JsonResponse({
            'success': False,
            'message': 'No pending registration found for this email.'
        }, status=400)
def UserLogin(request):
    if request.method == 'POST':
        email = request.POST.get('email')  # Using .get() to avoid KeyError
        password = request.POST.get('password')
        
        if not email or not password:
            messages.error(request, 'Both email and password are required.')
            return render(request, 'signin.html')
        
        # First check if user exists
        try:
            user = models.CustomUser.objects.get(email=email)
            
            if not user.is_active:
                messages.error(request, 'Account not verified. Please check your email.')
                return render(request, 'signin.html', {'unverified_email': email})
            
            # Authenticate using email as username
            authenticated_user = authenticate(request, username=email, password=password)
            
            if authenticated_user is not None:
                login(request, authenticated_user)
                messages.success(request, 'Logged in successfully!')
                next_url = request.GET.get('next', 'home')
                return redirect(next_url)
            else:
                # Check if password is correct manually (for debugging)
                if user.check_password(password):
                    # If password checks out but authenticate fails, there's a backend issue
                    messages.error(request, 'Authentication failed. Please try again.')
                else:
                    messages.error(request, 'Invalid password.')
                return render(request, 'signin.html', {'email': email})
                
        except models.CustomUser.DoesNotExist:
            messages.error(request, 'No account found with this email.')
            return render(request, 'signin.html')
    
    # This handles GET requests
    return render(request, 'signin.html')

def UserLogout(request):
    logout(request)
    messages.success(request,'Logged out successfully')
    return redirect('login')

@login_required
@require_POST
@ensure_csrf_cookie
def refresh_session(request):
    """
    Simple view to refresh the user's session when they choose to stay logged in
    """
    # Accessing the session modifies it, marking it as having been modified
    request.session.modified = True
    
    # You can also reset the session expiry time explicitly
    if not request.session.get('session_refreshed'):
        request.session['session_refreshed'] = True
    
    return JsonResponse({
        'status': 'success',
        'message': 'Session refreshed successfully',
        'timestamp': str(datetime.datetime.now())
    })
def UserForgotPassword(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        
        if models.CustomUser.objects.filter(email=email).exists():
            user = models.CustomUser.objects.get(email=email)
            
            # Generate and save a password reset token
            token = models.PasswordResetToken.objects.create(user=user)
            
            # Build the password reset URL
            reset_url = request.build_absolute_uri(
                reverse('password_reset_confirm', kwargs={'token': token.token})
            )
            
            # Send an email with the reset link
            subject = "Password Reset Request"
            message = (
                f"Dear {user.first_name},\n\n"
                f"You requested a password reset. Click the link below to set a new password:\n\n"
                f"{reset_url}\n\n"
                f"This link expires in 1 hour.\n\n"
                f"If you didn't request this, please ignore this email.\n\n"
                f"Best regards,\n"
                f"{settings.SITE_NAME}"
            )
            
            send_mail(
                subject=subject,
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[email],
                fail_silently=False,
            )
            
            messages.success(request, 'Password reset link sent! Check your email.')
            return redirect('login')
        else:
            messages.error(request, 'No account found with this email.')
            return render(request, 'reset-password.html')
    
    return render(request, 'reset-password.html')


def PasswordResetConfirm(request, token):
    try:
        reset_token = models.PasswordResetToken.objects.get(token=token)
        
        if not reset_token.is_valid():
            messages.error(request, 'This link has expired. Request a new one.')
            return redirect('forgot-password')
        
        if request.method == 'POST':
            new_password = request.POST.get('new_password')
            confirm_password = request.POST.get('confirm_new_password')
            
            if new_password != confirm_password:
                messages.error(request, 'Passwords do not match!')
                return render(request, 'confirm-password.html', {'token': token})
            
            # Check if new password is same as old password
            user = reset_token.user
            if check_password(new_password, user.password):
                messages.error(request, 'New password cannot be the same as your old password')
                return render(request, 'confirm-password.html', {'token': token})
            
            # Update the user's password
            user.set_password(new_password)
            user.save()
            
            # Delete the token
            reset_token.delete()
            
            messages.success(request, 'Password updated successfully! You can now log in.')
            return redirect('login')
        
        return render(request, 'confirm-password.html', {'token': token})
    
    except models.PasswordResetToken.DoesNotExist:
        messages.error(request, 'Invalid reset link. Request a new one.')
        return redirect('forgot-password')
    
def BingwaStore(request):
    packages = models.Package.objects.all()
    return render(request, 'bingwa.html', {'packages': packages})

@login_required
def add_package(request):
    if request.method == 'POST':
        form = PackageForm(request.POST)
        if form.is_valid():
            form.save()
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({
                    'success': True,
                    'message': 'Package added successfully!'
                })
            messages.success(request, 'Package added successfully!')
            return redirect('store')
        else:
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({
                    'success': False,
                    'message': 'Form validation failed!',
                    'errors': form.errors
                })
    else:
        form = PackageForm()
    
    return render(request, 'package.html', {'form': form, 'title': 'Add Package'})

@login_required
def edit_package(request, pk):
    package = get_object_or_404(models.Package, pk=pk)
    
    if request.method == 'POST':
        form = PackageForm(request.POST, instance=package)
        if form.is_valid():
            form.save()
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({
                    'success': True,
                    'message': 'Package updated successfully!'
                })
            messages.success(request, 'Package updated successfully!')
            return redirect('store')
        else:
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({
                    'success': False,
                    'message': 'Form validation failed!',
                    'errors': form.errors
                })
    else:
        form = PackageForm(instance=package)
    
    return render(request, 'package.html', {'form': form, 'title': 'Edit Package'})

@login_required
def delete_package(request, pk):
    package = get_object_or_404(models.Package, pk=pk)
    
    if request.method == 'POST':
        package_name = package.name
        package.delete()
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({
                'success': True,
                'message': f'"{package_name}" deleted successfully!'
            })
        messages.success(request, f'{package_name} deleted successfully!')
        return redirect('store')
    
    return render(request, 'package_delete.html', {'package': package})

@login_required
def profile_view(request):
    """View function to display user profile information"""
    try:
        # Get or create user profile
        profile, created = models.UserProfile.objects.get_or_create(user=request.user)
        
        return render(request, 'profile.html', {
            'profile': profile,
        })
    except Exception as e:
        messages.error(request, f"Error accessing profile: {str(e)}")
        return redirect('home')

@login_required
def profile_update(request):
    """View function to update user profile"""
    try:
        profile = request.user.profile
        
        if request.method == 'POST':
            form = ProfileUpdateForm(request.POST, request.FILES, instance=profile)
            if form.is_valid():
                # Save the profile first (this includes phone number)
                profile = form.save(commit=False)
                profile.phone = form.cleaned_data['phone']  # Explicitly set phone
                profile.save()
                
                # Update user model fields
                user = request.user
                user.first_name = form.cleaned_data['first_name']
                user.last_name = form.cleaned_data['last_name']
                user.email = form.cleaned_data['email']
                user.save()
                
                messages.success(request, "Your profile has been updated successfully!")
                return redirect('profile')
        else:
            form = ProfileUpdateForm(instance=profile, initial={
                'first_name': request.user.first_name,
                'last_name': request.user.last_name,
                'email': request.user.email,
                'phone': profile.phone,  # Make sure this is included
            })
        
        return render(request, 'profile_update.html', {
            'form': form,
            'profile': profile
        })
        
    except Exception as e:
        messages.error(request, f"Error updating profile: {str(e)}")
        return redirect('profile')
@login_required
def account_settings(request):
    # Initialize forms with current instances
    user = request.user
    profile = user.profile
    user_form = UserUpdateForm(instance=user)
    profile_form = ProfileUpdateForm(instance=profile)
    password_form = PasswordChangeCustomForm()
    deactivate_form = DeactivateAccountForm()

    if request.method == 'POST':
        if 'update_profile' in request.POST:
            user_form = UserUpdateForm(request.POST, instance=user)
            profile_form = ProfileUpdateForm(
                request.POST, 
                request.FILES, 
                instance=profile
            )
            
            if user_form.is_valid() and profile_form.is_valid():
                # Save user data first
                user = user_form.save()
                
                # Save profile data with proper date handling
                profile = profile_form.save(commit=False)
                profile.user = user  # Ensure relationship is maintained
                
                # Handle date of birth specifically
                if 'date_of_birth' in profile_form.cleaned_data:
                    profile.date_of_birth = profile_form.cleaned_data['date_of_birth']
                
                profile.save()
                
                messages.success(request, 'Your profile has been updated!')
                return redirect(reverse('account_settings') + '?tab=profile')

        elif 'change_password' in request.POST:
            password_form = PasswordChangeCustomForm(request.POST)
            
            if password_form.is_valid():
                current_password = password_form.cleaned_data.get('current_password')
                
                if user.check_password(current_password):
                    new_password = password_form.cleaned_data.get('new_password')
                    user.set_password(new_password)
                    user.save()
                    update_session_auth_hash(request, user)
                    messages.success(request, 'Your password has been updated!')
                    return redirect(reverse('account_settings') + '?tab=security')
                else:
                    messages.error(request, 'Current password is incorrect')

        elif 'deactivate_account' in request.POST:
            deactivate_form = DeactivateAccountForm(request.POST)
            if deactivate_form.is_valid():
                password = deactivate_form.cleaned_data.get('password')
                
                if user.check_password(password):
                    user.is_active = False
                    user.save()
                    logout(request)
                    messages.success(request, 'Your account has been deactivated.')
                    return redirect('home')
                else:
                    messages.error(request, 'Password is incorrect')
                    return redirect(reverse('account_settings') + '?tab=security')

    # Prepare context - use the forms we've already initialized
    context = {
        'user_form': user_form,
        'profile_form': profile_form,
        'password_form': password_form,
        'deactivate_form': deactivate_form,
        'active_tab': request.GET.get('tab', 'profile')
    }
    
    return render(request, 'settings.html', context)

@login_required
def reactivate_account(request, user_id):
    # Only staff/admin should access this
    if not request.user.is_staff:
        messages.error(request, "You don't have permission to perform this action.")
        return redirect('home')
    
    try:
        user = models.CustomUser.objects.get(id=user_id)
        user.is_active = True
        user.save()
        messages.success(request, f"Account for {user.email} has been reactivated.")
    except models.CustomUser.DoesNotExist:
        messages.error(request, "User not found.")
    
    return redirect('home')

def send_reactivation_email(request, user):
    """
    Send a reactivation email to the user with a secure token
    """
    # Generate token
    token = default_token_generator.make_token(user)
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    
    # Build the reactivation URL
    domain = request.get_host()
    reactivation_url = f"{request.scheme}://{domain}{reverse('reactivate_account', kwargs={'uidb64': uid, 'token': token})}"
    
    # Prepare email content
    subject = 'Reactivate Your Account'
    message = render_to_string('reactivation_email.html', {
        'user': user,
        'reactivation_url': reactivation_url,
        'valid_days': 7,  # Token validity period
    })
    
    # Send the email
    send_mail(
        subject,
        message,
        settings.DEFAULT_FROM_EMAIL,
        [user.email],
        html_message=message,
        fail_silently=False,
    )

def reactivate_account(request, uidb64, token):
    """
    View to handle the reactivation link
    """
    try:
        # Decode the user ID
        uid = urlsafe_base64_decode(uidb64).decode()
        user = models.CustomUser.objects.get(pk=uid)
        
        # Check if the token is valid
        if default_token_generator.check_token(user, token):
            # Reactivate the account
            user.is_active = True
            user.save()
            
            messages.success(request, 'Your account has been successfully reactivated! You can now log in.')
            return redirect('login')
        else:
            messages.error(request, 'The reactivation link is invalid or has expired.')
            return redirect('home')
    except (TypeError, ValueError, OverflowError, models.customUser.DoesNotExist):
        messages.error(request, 'The reactivation link is invalid.')
        return redirect('home')