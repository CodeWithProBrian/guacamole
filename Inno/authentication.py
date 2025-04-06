from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError

class CustomAuthBackend(ModelBackend):
    def authenticate(self, request, email=None, password=None, **kwargs):
        UserModel = get_user_model()
        try:
            # Check if user exists at all (active or inactive)
            user = UserModel.objects.get(email=email)  # Assuming email is your username field
            
            # First check if password is correct
            if user.check_password(password):
                # Then check if account is active
                if not user.is_active:
                    # Instead of returning None silently, raise a validation error
                    # that will be shown in the login form
                    raise ValidationError(
                        "This account has been deactivated. Please contact support if you wish to reactivate it."
                    )
                return user
            return None
        except UserModel.DoesNotExist:
            return None
        except ValidationError as e:
            # Re-raise the validation error to be caught by the login view
            raise ValidationError(e)