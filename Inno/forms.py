from django import forms
from . import models
class PurchaseForm(forms.Form):
    paying_number = forms.CharField(
        label="Your Phone Number",
        max_length=10,
        widget=forms.TextInput(attrs={'class': 'form-control form-control-lg', 'required': True})
    )
    amount = forms.DecimalField(
        widget=forms.HiddenInput()
    )

class OtherNumberPurchaseForm(forms.Form):
    paying_number = forms.CharField(
        label="Paying Phone Number",
        max_length=10,
        widget=forms.TextInput(attrs={'class': 'form-control form-control-lg', 'required': True})
    )
    receiving_number = forms.CharField(
        label="Receiving Phone Number",
        max_length=10,
        widget=forms.TextInput(attrs={'class': 'form-control form-control-lg', 'required': True})
    )
    amount = forms.DecimalField(
        widget=forms.HiddenInput()
    )

class PackageForm(forms.ModelForm):
    class Meta:
        model = models.Package
        fields = ['name', 'price', 'category']  # Add category field here
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control'}),
            'price': forms.TextInput(attrs={'class': 'form-control'}),
            'category': forms.Select(attrs={'class': 'form-control'}),
        }

class ProfileUpdateForm(forms.ModelForm):
    """Form for updating user profile information"""
    first_name = forms.CharField(max_length=150, required=False)
    last_name = forms.CharField(max_length=150, required=False)
    email = forms.EmailField(required=False)
    
    class Meta:
        model = models.UserProfile
        fields = ['phone', 'profile_picture']
        
    def __init__(self, *args, **kwargs):
        super(ProfileUpdateForm, self).__init__(*args, **kwargs)
        
        # Add Bootstrap classes to form fields
        for field_name, field in self.fields.items():
            field.widget.attrs['class'] = 'form-control'

class UserUpdateForm(forms.ModelForm):
    class Meta:
        model = models.CustomUser
        fields = ['first_name', 'last_name', 'email', 'phone']
        widgets = {
            'first_name': forms.TextInput(attrs={'class': 'form-control'}),
            'last_name': forms.TextInput(attrs={'class': 'form-control'}),
            'email': forms.EmailInput(attrs={'class': 'form-control', 'readonly': 'readonly'}),
            'phone': forms.TextInput(attrs={'class': 'form-control'}),
        }

class ProfileUpdateForm(forms.ModelForm):
    """Form for updating both user and profile information"""
    first_name = forms.CharField(
        max_length=150,
        required=True,
        widget=forms.TextInput(attrs={'placeholder': 'Enter your first name'})
    )
    last_name = forms.CharField(
        max_length=150,
        required=True,
        widget=forms.TextInput(attrs={'placeholder': 'Enter your last name'})
    )
    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={'readonly': 'readonly'})
    )
    phone = forms.CharField(
        max_length=20,
        required=False,
        widget=forms.TextInput(attrs={'placeholder': 'Enter phone number'})
    )
    date_of_birth = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={'type': 'date'}),
        input_formats=['%Y-%m-%d', '%m/%d/%Y', '%m/%d/%y']
    )

    class Meta:
        model = models.UserProfile
        fields = [
            'first_name', 'last_name', 'email', 'phone',
            'profile_picture', 'bio', 'location', 'date_of_birth',
            'website', 'twitter', 'linkedin'
        ]
        widgets = {
            'bio': forms.Textarea(attrs={'rows': 3, 'placeholder': 'Tell us about yourself'}),
            'location': forms.TextInput(attrs={'placeholder': 'City, Country'}),
            'website': forms.URLInput(attrs={'placeholder': 'https://example.com'}),
            'twitter': forms.TextInput(attrs={'placeholder': '@username'}),
            'linkedin': forms.TextInput(attrs={'placeholder': 'linkedin.com/in/username'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        # Initialize user fields from associated User model
        if self.instance and hasattr(self.instance, 'user'):
            user = self.instance.user
            self.fields['first_name'].initial = user.first_name
            self.fields['last_name'].initial = user.last_name
            self.fields['email'].initial = user.email
            
            # Format date for HTML5 date input
            if self.instance.date_of_birth:
                self.initial['date_of_birth'] = self.instance.date_of_birth.strftime('%Y-%m-%d')
        
        # Add consistent styling to all fields
        for field_name, field in self.fields.items():
            field.widget.attrs['class'] = 'form-control'
            if field_name == 'profile_picture':
                field.widget.attrs['class'] += ' form-control-file'
    
    def save(self, commit=True):
        profile = super().save(commit=False)
        
        # Update the associated User model
        if hasattr(profile, 'user'):
            user = profile.user
            user.first_name = self.cleaned_data['first_name']
            user.last_name = self.cleaned_data['last_name']
            user.email = self.cleaned_data['email']
            if commit:
                user.save()
        
        if commit:
            profile.save()
            self.save_m2m()  # For any many-to-many relations
            
        return profile

class PasswordChangeCustomForm(forms.Form):
    current_password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control'}))
    new_password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control'}))
    confirm_password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control'}))

    def clean(self):
        cleaned_data = super().clean()
        new_password = cleaned_data.get('new_password')
        confirm_password = cleaned_data.get('confirm_password')
        
        if new_password and confirm_password and new_password != confirm_password:
            raise forms.ValidationError("New passwords don't match")
        
        return cleaned_data

class DeactivateAccountForm(forms.Form):
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={'class': 'form-control', 'id': 'deactivatePassword'}),
        label="Password"
    )