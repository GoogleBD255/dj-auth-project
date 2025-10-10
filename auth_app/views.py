from django.shortcuts import render, redirect, get_object_or_404
from .forms import UserRegisterForm, UserLoginForm
from .models import User, OTP
from .token import TokenGenerator
from django.utils import timezone
from django.contrib import messages
from django.core.mail import send_mail, EmailMultiAlternatives
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login, logout
import random
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.conf import settings
from django.http import request
from django.urls import resolve
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth import update_session_auth_hash
from django.http import HttpResponse
from .models import LoginAttempt
from datetime import timedelta

# Create your views here.




def get_client_ip(request):
    # নিরাপদভাবে IP বের করা
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        ip = x_forwarded_for.split(",")[0]
    else:
        ip = request.META.get("REMOTE_ADDR")
    return ip


@login_required(login_url='signin')
def home(request):

    context = {}

    return render(request, "home.html", context)


def signup(request):
    if request.user.is_authenticated == False:
        
        if request.method == "POST":

            email = request.POST['email']
            username = request.POST['username']
            password1 = request.POST['password1']
            password2 = request.POST['password2']

            if User.objects.filter(email=email).exists():
                messages.error(request, "Email alredy taken!")
                return render(request, "signup.html")
            
            elif User.objects.filter(username=username).exists():
                messages.error(request, "Username alredy taken!")
                return render(request, "signup.html")
            
            elif password1 != password2:
                messages.error(request, "Passwords do not match!")
                return render(request, "signup.html")
            
            else:
                user = User.objects.create(email=email, username=username)
                user.set_password(password1)

                if user is not None:
                    otp = OTP.objects.create(user=user, otp=random.randint(100000, 999999), otp_expire=timezone.now() + timezone.timedelta(minutes=2))
                    user.save()


                    context = {
                        'username':user.username,
                        'otp':otp.otp,
                    }

                    html_content =  render_to_string(template_name="otp_email.html", context=context)

                    subject="Email Verification"
                    body = "Email from ADMIN"
                    from_email = settings.DEFAULT_FROM_EMAIL
                    to = [user.email, ]
                
                
                    # send email
                    email = EmailMultiAlternatives(
                            subject,
                            body,
                            from_email,
                            to,
                        )
                    email.attach_alternative(html_content, "text/html")
                    email.send()
                    messages.success(request, "Account created successfully please verify your acccount")
                    return redirect("verify_otp", username = request.POST['username'])
                
        return render(request, "signup.html")     
       
    else:
        messages.warning(request, "You are already authenticated!")
        return redirect("home")
    
    

    





def verify_otp(request, username):
    if request.user.is_authenticated == False:

        user = User.objects.get(username=username)
        otp = OTP.objects.filter(user=user).last()
        
        
        if request.method == 'POST':
            # valid token
            if otp.otp == request.POST['otp']:
                
                # checking for expired token
                if otp.otp_expire > timezone.now():
                    if user.is_active == False:
                        user.is_active=True
                        user.save()
                        otp.delete()
                        messages.success(request, f"Account verified successfully, Now login")
                        return redirect("signin")
                    else:
                        messages.warning(request, f"You are alredy verified, put otp to login")
                        return redirect("login_with_otp", username=username)

                else:
                    messages.error(request, f"Your OTP is no longer valid!")
                    return redirect("verify_otp", username=username)
        return render(request, "verify_otp.html")

    else:
        messages.warning(request, f"You are already authenticated!")
        return redirect("home")
    

    






def resend_otp(request):
    if request.user.is_authenticated == False:

        if request.method == 'POST':
            user_email = request.POST["otp_email"]
            
            if User.objects.filter(email=user_email).exists():
                user = User.objects.get(email=user_email)

                if user.is_active == False:
                    otp = OTP.objects.create(user=user, otp=random.randrange(100000, 999999), otp_expire=timezone.now() + timezone.timedelta(minutes=2))
                
                    context = {
                        'username':user.username,
                        'otp':otp.otp,
                    }

                    html_content =  render_to_string(template_name="otp_email.html", context=context)

                    subject="Email Verification"
                    body = "Email from ADMIN"
                    from_email = settings.DEFAULT_FROM_EMAIL
                    to = [user_email,]
                
                
                    # send email
                    email = EmailMultiAlternatives(
                            subject,
                            body,
                            from_email,
                            to,
                        )
                    email.attach_alternative(html_content, "text/html")
                    email.send()
                    messages.success(request, f"Please check your email and verify")
                    return redirect("verify_otp", user.username)
                
                else:
                    otp = OTP.objects.create(user=user, otp=random.randrange(100000, 999999), otp_expire=timezone.now() + timezone.timedelta(minutes=2))
                
                    context = {
                        'username':user.username,
                        'otp':otp.otp,
                    }

                    html_content =  render_to_string(template_name="otp_email.html", context=context)

                    subject="Login Attempt Verification"
                    body = "Email from ADMIN"
                    from_email = settings.DEFAULT_FROM_EMAIL
                    to = [user_email,]
                
                
                    # send email
                    email = EmailMultiAlternatives(
                            subject,
                            body,
                            from_email,
                            to,
                        )
                    email.attach_alternative(html_content, "text/html")
                    email.send()
                    messages.success(request, f"You are alredy verified, please check your email and put otp to login")
                    return redirect("login_with_otp", username=user.username)

            else:
                messages.warning(request, f"This email is not in our list!")
                return render(request, "resend_otp.html")
            
            
        
        return render(request, "resend_otp.html")

    else:
        messages.warning(request, f"You are already authenticated!")
        return redirect("home")
    






def signin(request):
    if request.user.is_authenticated == False:
        
        if request.method == "POST":

            ip = get_client_ip(request)
            attempt, created = LoginAttempt.objects.get_or_create(ip_address=ip)

            # Check if blocked
            if attempt.is_blocked():
                remaining = (attempt.blocked_until - timezone.now()).seconds // 60
                return HttpResponse(
                    f"⚠️ Too many failed attempts! Try again after {remaining} minutes.",
                    status=403
                )

            email = request.POST['email']
            password = request.POST['password']

            if User.objects.filter(email=email).exists():
                user = User.objects.get(email=email)

                if user.is_active:

                    username = user.username
                    user = authenticate(request, 
                                        username=email, 
                                        password=password,)
                                        # backend='auth_config.backends.EmailBackend')

                    if user is not None:


                        
                        otp = OTP.objects.create(user=user, otp=random.randrange(100000, 999999), otp_expire=timezone.now() + timezone.timedelta(minutes=2))
                    
                    
                        context = {
                            'username':user.username,
                            'otp':otp.otp,
                        }

                        html_content =  render_to_string(template_name="otp_email.html", context=context)
                    
                        subject="Login Attempt Verification"
                        body = "Email from ADMIN"
                        from_email = settings.DEFAULT_FROM_EMAIL
                        to = [user.email, ]
                    
                    
                        # send email
                        email = EmailMultiAlternatives(
                                subject,
                                body,
                                from_email,
                                to,
                            )
                        email.attach_alternative(html_content, "text/html")
                        email.send()
                        
                        messages.success(request, f"Please check your email and verify your login attempt")
                        return redirect("login_with_otp", username=username)

                    else:
                        attempt.register_failed_attempt()
                        left = 3 - attempt.attempts if attempt.attempts < 3 else 0
                        messages.error(request, f"Email or password may be wrong! {left} tries left.")
                        return render(request, "signin.html")


                    
                else:
                    otp = OTP.objects.create(user=user, otp=random.randrange(100000, 999999), otp_expire=timezone.now() + timezone.timedelta(minutes=2))
                
                    context = {
                        'username':user.username,
                        'otp':otp.otp,
                    }

                    html_content =  render_to_string(template_name="otp_email.html", context=context)

                    subject="Email Verification"
                    body = "Email from ADMIN"
                    from_email = settings.DEFAULT_FROM_EMAIL
                    to = [user.email,]
                
                
                    # send email
                    email = EmailMultiAlternatives(
                            subject,
                            body,
                            from_email,
                            to,
                        )
                    email.attach_alternative(html_content, "text/html")
                    email.send()
                    messages.success(request, f"Please check your email and verify")
                    return redirect("verify_otp", user.username)

                
            else:
                messages.warning(request, f"This email is not in our list!")
                return render(request, "signin.html")
            
        return render(request, "signin.html")  


    else:
        messages.warning(request, f"You are already authenticated!")
        return redirect("home")
    

    





def login_with_otp(request, username):
    if request.user.is_authenticated == False:

        user = User.objects.get(username=username)
        otp = OTP.objects.filter(user=user).last()
        
        
        if request.method == 'POST':
            # valid token
            if otp.otp == request.POST['otp']:
                
                # checking for expired token
                if otp.otp_expire > timezone.now():
                    user = get_object_or_404(User, username=user.username)    
                    login(request, user)
                    otp.delete()
                    messages.success(request, f"Hi {user.username}, you are now logged-in")
                    return redirect("home")
                else:
                    messages.error(request, f"Your OTP is no longer valid!")
                    return redirect("login_with_otp", user.username)
        return render(request, "login_with_otp.html")

    else:
        messages.warning(request, f"You are already authenticated!")
        return redirect("home")
    






def signout(request):
    logout(request)
    messages.success(request, "Logout successfully")
    return redirect("signin")






def forgot_password(request):
    if request.user.is_authenticated == False:

        if request.method == 'POST':
            email = request.POST['email']
            
            if User.objects.filter(email=email).exists():
                user = User.objects.get(email=email)
                uid = urlsafe_base64_encode(force_bytes(user.pk))
                token = default_token_generator.make_token(user)
                reset_link = request.build_absolute_uri(f"/reset-password/{uid}/{token}/")

                context = {
                    'username':user.username,
                    'reset_link':reset_link,
                }

                html_content =  render_to_string(template_name="pass_reset_email.html", context=context)

                subject="Reset Your Password"
                body = "Email from ADMIN"
                from_email = settings.DEFAULT_FROM_EMAIL
                to = [user.email,]
            
            
                # send email
                email = EmailMultiAlternatives(
                        subject,
                        body,
                        from_email,
                        to,
                    )
                email.attach_alternative(html_content, "text/html")
                email.send()
                messages.success(request, f"Please check your email and click the link to reset your password")
                return render(request, "forgot_password.html")
            
            else:
                messages.error(request, f"User does not found!")
                return render(request, "forgot_password.html")
            
        return render(request, "forgot_password.html")
    
    else:
        messages.warning(request, f"You are already authenticated!")
        return redirect("home")








def reset_password(request, uidb64, token):
    if request.user.is_authenticated == False:

        token_generator = TokenGenerator(expiry_minutes=2)

        try:
            uid = force_bytes(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except(User.DoesNotExist, ValueError, TabError):
            user = None

        if user and token_generator.check_token(user, token):
            if request.method == 'POST':
                new_pass1 = request.POST['new_pass1']
                new_pass2 = request.POST['new_pass2']

                if new_pass1 == new_pass2:
                    user.set_password(new_pass1)
                    user.save()
                    messages.success(request, f"Your password reset successfully")
                    return redirect("signin")
                else:
                    messages.error(request, f"Password does not match!")
                    return render(request, "reset_password.html")

        else:
            messages.error(request, f"User does not found or token has expired")
            return redirect("forgot_password")
        
        return render(request, "reset_password.html")

    else:
        messages.warning(request, f"You are already authenticated!")
        return redirect("home")






def change_pass(request):
    if request.user.is_authenticated:
        if request.method == 'POST':
            user = request.user
            old_password = request.POST.get('old_password')
            new_password = request.POST.get('new_password')
            new_password2 = request.POST.get('new_password2')

            if user.check_password(old_password):
                if new_password == new_password2:
                    user.set_password(new_password)
                    user.save()
                    update_session_auth_hash(request, user)
                    messages.success(request, "Password changed successfully")
                    return redirect("home") 
                else:
                    messages.error(request, "Passwords do not match!")
                    return render(request, "change_pass.html")
            else:
                messages.error(request, "Old password is not correct!")
                return render(request, "change_pass.html")

        # This line handles GET requests
        return render(request, "change_pass.html")

    else:
        messages.warning(request, "You are unauthenticated!")
        return redirect("signin")









def view_404(request, exception):
    return render(request, '404.html', status=404)