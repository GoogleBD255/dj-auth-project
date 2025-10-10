from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth import get_user_model


class UserRegisterForm(UserCreationForm):
    email=forms.CharField(widget=forms.EmailInput(attrs={"placeholder": "Enter email-address", "class": "form-control"}))
    username=forms.CharField(widget=forms.TextInput(attrs={"placeholder": "Enter email-username", "class": "form-control"}))
    password1=forms.CharField(label="Password", widget=forms.PasswordInput(attrs={"placeholder": "Enter password", "class": "form-control"}))
    password2=forms.CharField(label="Confirm Password", widget=forms.PasswordInput(attrs={"placeholder": "Confirm password", "class": "form-control"}))
    
    class Meta:
        model = get_user_model()
        fields = ["email", "username", "password1", "password2"]


class UserLoginForm(AuthenticationForm):
    email = forms.CharField(label="Email address", widget=forms.EmailInput(attrs={"class":"form-control"}))
    pass1 = forms.CharField(label="Password", widget=forms.PasswordInput(attrs={"class":"form-control"}))

    class Meta:
        model = get_user_model()
        fields = ["email", "password1"]