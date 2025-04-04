from django import forms
from . import models
class PurchaseForm(forms.Form):
    paying_number = forms.CharField(
        label="Your Phone Number",
        max_length=15,
        widget=forms.TextInput(attrs={'class': 'form-control form-control-lg', 'required': True})
    )
    amount = forms.DecimalField(
        widget=forms.HiddenInput()
    )

class OtherNumberPurchaseForm(forms.Form):
    paying_number = forms.CharField(
        label="Paying Phone Number",
        max_length=15,
        widget=forms.TextInput(attrs={'class': 'form-control form-control-lg', 'required': True})
    )
    receiving_number = forms.CharField(
        label="Receiving Phone Number",
        max_length=15,
        widget=forms.TextInput(attrs={'class': 'form-control form-control-lg', 'required': True})
    )
    amount = forms.DecimalField(
        widget=forms.HiddenInput()
    )

class PackageForm(forms.ModelForm):
    class Meta:
        model = models.Package
        fields = ['name', 'price', 'ussd', 'validity', 'retry']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control'}),
            'price': forms.TextInput(attrs={'class': 'form-control'}),
            'ussd': forms.TextInput(attrs={'class': 'form-control'}),
            'validity': forms.NumberInput(attrs={'class': 'form-control'}),
            'retry': forms.NumberInput(attrs={'class': 'form-control'}),
        }