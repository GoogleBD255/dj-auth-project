from django.shortcuts import render, redirect, get_object_or_404
from .forms import UserRegisterForm, UserLoginForm
from .models import User, OTP
from .token import TokenGenerator
from django.utils import timezone
from django.contrib import messages
from django.core.mail import EmailMultiAlternatives
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.urls import reverse_lazy
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.tokens import default_token_generator
from django.template.loader import render_to_string
from django.conf import settings
from django.http import HttpResponse
import random


# ------------------------
# Utility Functions
# ------------------------
def get_client_ip(request):
    """নিরাপদভাবে ক্লায়েন্ট IP বের করা"""
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        ip = x_forwarded_for.split(",")[0]
    else:
        ip = request.META.get("REMOTE_ADDR")
    return ip


# ------------------------
# Authenticated Pages
# ------------------------
@login_required(login_url='signin')
def home(request):
    return render(request, "home.html", {})


# ------------------------
# Signup & OTP Verification
# ------------------------
def signup(request):
    if request.user.is_authenticated:
        messages.warning(request, "You are already authenticated!")
        return redirect("home")

    if request.method == "POST":
        email = request.POST.get('email')
        username = request.POST.get('username')
        password1 = request.POST.get('password1')
        password2 = request.POST.get('password2')

        if User.objects.filter(email=email).exists():
            messages.error(request, "Email already taken!")
            return render(request, "signup.html")

        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already taken!")
            return render(request, "signup.html")

        if password1 != password2:
            messages.error(request, "Passwords do not match!")
            return render(request, "signup.html")

        user = User.objects.create(email=email, username=username)
        user.set_password(password1)
        user.save()

        otp = OTP.objects.create(
            user=user,
            otp=random.randint(100000, 999999),
            otp_expire=timezone.now() + timezone.timedelta(minutes=2)
        )

        context = {'username': user.username, 'otp': otp.otp}
        html_content = render_to_string("otp_email.html", context)
        subject = "Email Verification"
        from_email = settings.DEFAULT_FROM_EMAIL
        to = [user.email]

        email_msg = EmailMultiAlternatives(subject, "Email from ADMIN", from_email, to)
        email_msg.attach_alternative(html_content, "text/html")
        email_msg.send()

        messages.success(request, "Account created successfully. Please verify your account.")
        return redirect("verify_otp", username=username)

    return render(request, "signup.html")


def verify_otp(request, username):
    if request.user.is_authenticated:
        messages.warning(request, "You are already authenticated!")
        return redirect("home")

    user = get_object_or_404(User, username=username)
    otp = OTP.objects.filter(user=user).last()

    if user.is_active:
        messages.warning(request, "You are already verified. Please login using OTP!")
        return redirect("login_with_otp", username=username)

    if request.method == 'POST':
        entered_otp = request.POST.get('otp')
        if otp and str(otp.otp) == entered_otp:
            if otp.otp_expire > timezone.now():
                user.is_active = True
                user.save()
                otp.delete()
                messages.success(request, "Account verified successfully. Now login.")
                return redirect("signin")
            else:
                messages.error(request, "Your OTP is no longer valid!")
                return redirect("verify_otp", username=username)
        else:
            messages.error(request, "Invalid OTP!")
            return render(request, "verify_otp.html")

    return render(request, "verify_otp.html")


def resend_otp(request):
    if request.user.is_authenticated:
        messages.warning(request, "You are already authenticated!")
        return redirect("home")

    if request.method == 'POST':
        user_email = request.POST.get("otp_email")
        user = User.objects.filter(email=user_email).first()
        if not user:
            messages.warning(request, "This email is not in our list!")
            return render(request, "resend_otp.html")

        otp = OTP.objects.create(
            user=user,
            otp=random.randint(100000, 999999),
            otp_expire=timezone.now() + timezone.timedelta(minutes=2)
        )

        context = {'username': user.username, 'otp': otp.otp}
        html_content = render_to_string("otp_email.html", context)

        subject = "Email Verification" if not user.is_active else "Login Attempt Verification"
        from_email = settings.DEFAULT_FROM_EMAIL
        to = [user_email]

        email_msg = EmailMultiAlternatives(subject, "Email from ADMIN", from_email, to)
        email_msg.attach_alternative(html_content, "text/html")
        email_msg.send()

        messages.success(request, "Please check your email and verify.")
        if user.is_active:
            return redirect("login_with_otp", username=user.username)
        return redirect("verify_otp", username=user.username)

    return render(request, "resend_otp.html")


# ------------------------
# Signin & Login with OTP
# ------------------------
def signin(request):
    if request.user.is_authenticated:
        messages.warning(request, "You are already authenticated!")
        return redirect("home")

    if request.method == "POST":
        email = request.POST.get('email')
        password = request.POST.get('password')
        ip = get_client_ip(request)

        user = User.objects.filter(email=email).first()
        if not user:
            messages.warning(request, "This email is not in our list!")
            return render(request, "signin.html")

        if user.is_active:
            auth_user = authenticate(request, username=email, password=password)
            if auth_user:
                otp = OTP.objects.create(
                    user=user,
                    otp=random.randint(100000, 999999),
                    otp_expire=timezone.now() + timezone.timedelta(minutes=2)
                )
                context = {
                    'username': user.username,
                    'otp': otp.otp,
                    'ip': f"Someone trying to access your account from {ip}. If it's you, use the OTP."
                }
                html_content = render_to_string("otp_email.html", context)
                email_msg = EmailMultiAlternatives(
                    "Login Attempt Verification", "Email from ADMIN",
                    settings.DEFAULT_FROM_EMAIL, [user.email]
                )
                email_msg.attach_alternative(html_content, "text/html") 
                email_msg.send()
                messages.success(request, "Please check your email and verify your login attempt.")
                return redirect("login_with_otp", username=user.username)
            else:
                messages.error(request, "Email or password may be wrong!")
                return render(request, "signin.html")
        elif not user.is_active:
            # send verification OTP if not active
            otp = OTP.objects.create(
                user=user,
                otp=random.randint(100000, 999999),
                otp_expire=timezone.now() + timezone.timedelta(minutes=2)
            )
            context = {'username': user.username, 'otp': otp.otp}
            html_content = render_to_string("otp_email.html", context)
            email_msg = EmailMultiAlternatives(
                "Email Verification", "Email from ADMIN",
                settings.DEFAULT_FROM_EMAIL, [user.email]
            )
            email_msg.attach_alternative(html_content, "text/html")
            email_msg.send()
            messages.success(request, "Please check your email and verify.")
            return redirect("verify_otp", username=user.username)
        else:
            messages.error(request, "Somsthing went wrong, Please try again.")
            return redirect("signin")
    return render(request, "signin.html")


def login_with_otp(request, username):
    if request.user.is_authenticated:
        messages.warning(request, "You are already authenticated!")
        return redirect("home")

    user = get_object_or_404(User, username=username)
    otp = OTP.objects.filter(user=user).last()

    if request.method == 'POST':
        entered_otp = request.POST.get('otp')
        if otp and str(otp.otp) == entered_otp:
            if otp.otp_expire > timezone.now():
                login(request, user)
                otp.delete()
                request.session['session_expirey'] = timezone.now().timestamp()
                messages.success(request, f"Hi {user.username}, you are now logged-in")
                return redirect("home")
            else:
                messages.error(request, "Your OTP is no longer valid!")
                return redirect("login_with_otp", username=user.username)
        else:
            messages.error(request, "Invalid OTP!")

    return render(request, "login_with_otp.html")


def signout(request):
    logout(request)
    messages.success(request, "Logged out successfully")
    return redirect("signin")


# ------------------------
# Password Management
# ------------------------
def forgot_password(request):
    if request.user.is_authenticated:
        messages.warning(request, "You are already authenticated!")
        return redirect("home")

    if request.method == 'POST':
        email = request.POST.get('email')
        ip = get_client_ip(request)
        user = User.objects.filter(email=email).first()

        if not user:
            messages.error(request, "User not found!")
            return render(request, "forgot_password.html")

        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        reset_link = request.build_absolute_uri(f"/reset-password/{uid}/{token}/")

        context = {
            'username': user.username,
            'reset_link': reset_link,
            'ip': f"Someone tried to reset your password from {ip}. If it's you, use the link."
        }
        html_content = render_to_string("pass_reset_email.html", context)
        email_msg = EmailMultiAlternatives(
            "Reset Your Password", "Email from ADMIN",
            settings.DEFAULT_FROM_EMAIL, [user.email]
        )
        email_msg.attach_alternative(html_content, "text/html")
        email_msg.send()
        messages.success(request, "Please check your email and click the link to reset your password.")
        return render(request, "forgot_password.html")

    return render(request, "forgot_password.html")


def reset_password(request, uidb64, token):
    if request.user.is_authenticated:
        messages.warning(request, "You are already authenticated!")
        return redirect("home")

    token_generator = TokenGenerator(expiry_minutes=2)
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (User.DoesNotExist, ValueError, TypeError):
        user = None

    if not user or not token_generator.check_token(user, token):
        messages.error(request, "User not found or token has expired")
        return redirect("forgot_password")

    if request.method == 'POST':
        new_pass1 = request.POST.get('new_pass1')
        new_pass2 = request.POST.get('new_pass2')
        if new_pass1 == new_pass2:
            user.set_password(new_pass1)
            user.save()
            messages.success(request, "Your password was reset successfully")
            return redirect("signin")
        else:
            messages.error(request, "Passwords do not match!")

    return render(request, "reset_password.html")


@login_required(login_url='signin')
def change_pass(request):
    if request.method == 'POST':
        user = request.user
        old_password = request.POST.get('old_password')
        new_password = request.POST.get('new_password')
        new_password2 = request.POST.get('new_password2')

        if not user.check_password(old_password):
            messages.error(request, "Old password is incorrect!")
            return render(request, "change_pass.html")

        if new_password != new_password2:
            messages.error(request, "Passwords do not match!")
            return render(request, "change_pass.html")

        user.set_password(new_password)
        user.save()
        update_session_auth_hash(request, user)
        messages.success(request, "Password changed successfully")
        return redirect("home")

    return render(request, "change_pass.html")


# ------------------------
# Admin Login & Key Verification
# ------------------------
def admin_login(request):
    if request.user.is_authenticated:
        messages.warning(request, "You are already in session!")
        return redirect("admin:index")

    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')

        user = authenticate(request, username=email, password=password)
        if user and user.is_staff:
            request.session['admin_logging'] = True
            request.session['admin_user'] = user.username
            messages.success(request, "Admin identity approved, now enter the key to access your dashboard")
            return redirect("key_verify")
        messages.error(request, "You are not admin!")
        return redirect("admin_login")

    return render(request, "admin_login.html")


def key_verify(request):
    if not request.session.get('admin_logging'):
        return redirect('admin_login')

    username = request.session.get('admin_user')
    user = get_object_or_404(User, username=username)

    if request.method == 'POST':
        key = request.POST.get('key')
        if key == "admin123" and user.is_staff:
            login(request, user)
            request.session.pop('admin_logging', None)
            request.session.cycle_key()
            messages.success(request, "Admin logged-in successfully")
            return redirect('admin:index')
        messages.error(request, "You are not Admin or wrong key!")
        return redirect('key_verify')

    return render(request, "key_verify.html")


# ------------------------
# Custom 404 Page
# ------------------------
def view_404(request, exception):
    return render(request, '404.html', status=404)






















# from django.shortcuts import render, redirect, get_object_or_404
# from .forms import UserRegisterForm, UserLoginForm
# from .models import User, OTP
# from .token import TokenGenerator
# from django.utils import timezone
# from django.contrib import messages
# from django.core.mail import send_mail, EmailMultiAlternatives
# from django.contrib.auth.decorators import login_required
# from django.contrib.auth import authenticate, login, logout
# import random
# import re
# from django.template.loader import render_to_string
# from django.utils.html import strip_tags
# from django.conf import settings
# from django.http import request
# from django.urls import resolve
# from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
# from django.utils.encoding import force_bytes, force_str
# from django.contrib.auth.tokens import default_token_generator
# from django.contrib.auth import update_session_auth_hash
# from django.http import HttpResponse
# from django.contrib.admin.views.decorators import staff_member_required
# from django.contrib.auth.views import LoginView
# from django.urls import reverse_lazy
# from django.contrib.admin.models import LogEntry
# from django.contrib.admin.sites import site

# # Create your views here.





# # def admin_login(request):
# #     if request.user.is_authenticated == False:
# #         if request.method == 'POST':
# #             email = request.POST['email']
# #             password = request.POST['password']

# #             user = authenticate(request, username=email, password=password)
# #             if user is not None and user.is_staff:
# #                 request.session['admin_logging'] = True
# #                 request.session['admin_user'] = user.username
# #                 messages.success(request, "Admin identity approved, now enter the key to access your dashboard")
# #                 return redirect("key_verify")
# #             else:
# #                 messages.error(request, "You are not admin!")
# #                 return redirect("admin_login")
# #         return render(request, "admin_login.html")
# #     else:
# #         messages.warning(request, "You are already in session!")
# #         return redirect("admin:index")

    
# # def key_verify(request):
# #     if request.session.get('admin_logging'):
# #         username = request.session.get('admin_user')
# #         user = get_object_or_404(User, username=username)
# #         if request.method == 'POST':
# #             key = request.POST['key']
# #             if key == "admin123" and user.is_staff:
# #                 login(request, user)
# #                 request.session.pop('admin_logging', None)
# #                 request.session.cycle_key()
# #                 messages.success(request, "Admin logged-in successfully")
# #                 return redirect('admin:index')
# #             else:
# #                 messages.error(request, "You are not Admin or wrong key!")
# #                 return redirect('key_verify')
    
# #         return render(request, "key_verify.html")
# #     else:
# #         return redirect('admin_login')

# def get_client_ip(request):
#     # নিরাপদভাবে IP বের করা
#     x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
#     if x_forwarded_for:
#         ip = x_forwarded_for.split(",")[0]
#     else:
#         ip = request.META.get("REMOTE_ADDR")
#     return ip


# @login_required(login_url='signin')
# def home(request):

#     context = {}

#     return render(request, "home.html", context)




# def signup(request):
#     if request.user.is_authenticated == False:
        
#         if request.method == "POST":

#             emailRegex = r'^[a-zA-Z0-9._%+-]+@gmail+\.com$'

#             email = request.POST['email']
#             username = request.POST['username']
#             password1 = request.POST['password1']
#             password2 = request.POST['password2']

#             if User.objects.filter(email=email).exists():
#                 messages.error(request, "Email alredy taken!")
#                 return render(request, "signup.html")
            
#             elif User.objects.filter(username=username).exists():
#                 messages.error(request, "Username alredy taken!")
#                 return render(request, "signup.html")
            
            
#             elif password1 != password2:
#                 messages.error(request, "Passwords do not match!")
#                 return render(request, "signup.html")
            
#             else:
#                 user = User.objects.create(email=email, username=username)
#                 user.set_password(password1)

#                 if user is not None:
#                     otp = OTP.objects.create(user=user, otp=random.randint(100000, 999999), otp_expire=timezone.now() + timezone.timedelta(minutes=2))
#                     user.save()


#                     context = {
#                         'username':user.username,
#                         'otp':otp.otp,
#                     }

#                     html_content =  render_to_string(template_name="otp_email.html", context=context)

#                     subject="Email Verification"
#                     body = "Email from ADMIN"
#                     from_email = settings.DEFAULT_FROM_EMAIL
#                     to = [user.email, ]
                
                
#                     # send email
#                     email = EmailMultiAlternatives(
#                             subject,
#                             body,
#                             from_email,
#                             to,
#                         )
#                     email.attach_alternative(html_content, "text/html")
#                     email.send()
#                     messages.success(request, "Account created successfully please verify your acccount")
#                     return redirect("verify_otp", username = request.POST['username'])
                
#         return render(request, "signup.html")     
       
#     else:
#         messages.warning(request, "You are already authenticated!")
#         return redirect("home")
    
    

    





# def verify_otp(request, username):
#     if request.user.is_authenticated == False:

#         user = User.objects.get(username=username)
#         otp = OTP.objects.filter(user=user).last()
        
#         if user.is_active:
#             messages.warning(request, "You are alredy verified, put otp to login!")
#             return redirect("login_with_otp", username=username)
        
#         if request.method == 'POST':
#             # valid token
#             if otp.otp == request.POST['otp']:
                
#                 # checking for expired token
#                 if otp.otp_expire > timezone.now():
#                     user.is_active=True
#                     user.save()
#                     otp.delete()
#                     messages.success(request, f"Account verified successfully, Now login")
#                     return redirect("signin")
#                 else:
#                     messages.error(request, f"Your OTP is no longer valid!")
#                     return redirect("verify_otp", username=username)
#         return render(request, "verify_otp.html")

#     else:
#         messages.warning(request, f"You are already authenticated!")
#         return redirect("home")
    

    






# def resend_otp(request):
#     if request.user.is_authenticated == False:

#         if request.method == 'POST':
#             user_email = request.POST["otp_email"]
            
#             if User.objects.filter(email=user_email).exists():
#                 user = User.objects.get(email=user_email)

#                 if user.is_active == False:
#                     otp = OTP.objects.create(user=user, otp=random.randrange(100000, 999999), otp_expire=timezone.now() + timezone.timedelta(minutes=2))
                
#                     context = {
#                         'username':user.username,
#                         'otp':otp.otp,
#                     }

#                     html_content =  render_to_string(template_name="otp_email.html", context=context)

#                     subject="Email Verification"
#                     body = "Email from ADMIN"
#                     from_email = settings.DEFAULT_FROM_EMAIL
#                     to = [user_email,]
                
                
#                     # send email
#                     email = EmailMultiAlternatives(
#                             subject,
#                             body,
#                             from_email,
#                             to,
#                         )
#                     email.attach_alternative(html_content, "text/html")
#                     email.send()
#                     messages.success(request, f"Please check your email and verify")
#                     return redirect("verify_otp", user.username)
                
#                 else:
#                     otp = OTP.objects.create(user=user, otp=random.randrange(100000, 999999), otp_expire=timezone.now() + timezone.timedelta(minutes=2))
                
#                     context = {
#                         'username':user.username,
#                         'otp':otp.otp,
#                     }

#                     html_content =  render_to_string(template_name="otp_email.html", context=context)

#                     subject="Login Attempt Verification"
#                     body = "Email from ADMIN"
#                     from_email = settings.DEFAULT_FROM_EMAIL
#                     to = [user_email,]
                
                
#                     # send email
#                     email = EmailMultiAlternatives(
#                             subject,
#                             body,
#                             from_email,
#                             to,
#                         )
#                     email.attach_alternative(html_content, "text/html")
#                     email.send()
#                     messages.success(request, f"You are alredy verified, please check your email and put otp to login")
#                     return redirect("login_with_otp", username=user.username)

#             else:
#                 messages.warning(request, f"This email is not in our list!")
#                 return render(request, "resend_otp.html")
            
            
        
#         return render(request, "resend_otp.html")

#     else:
#         messages.warning(request, f"You are already authenticated!")
#         return redirect("home")
    






# def signin(request):
#     if request.user.is_authenticated == False:
        
#         if request.method == "POST":

#             ip = get_client_ip(request)

#             email = request.POST['email']
#             password = request.POST['password']

#             if User.objects.filter(email=email).exists():
#                 user = User.objects.get(email=email)

#                 if user.is_active:

#                     username = user.username
#                     user = authenticate(request, 
#                                         username=email, 
#                                         password=password,)
#                                         # backend='auth_config.backends.EmailBackend')

#                     if user is not None:


                        
#                         otp = OTP.objects.create(user=user, otp=random.randrange(100000, 999999), otp_expire=timezone.now() + timezone.timedelta(minutes=2))
                    
                    
#                         context = {
#                             'username':user.username,
#                             'otp':otp.otp,
#                             'ip': f"Someone trying to access your account from this address - {ip}. If it's your attempt then apply the OTP.",
#                         }

#                         html_content =  render_to_string(template_name="otp_email.html", context=context)
                    
#                         subject="Login Attempt Verification"
#                         body = "Email from ADMIN"
#                         from_email = settings.DEFAULT_FROM_EMAIL
#                         to = [user.email, ]
                    
                    
#                         # send email
#                         email = EmailMultiAlternatives(
#                                 subject,
#                                 body,
#                                 from_email,
#                                 to,
#                             )
#                         email.attach_alternative(html_content, "text/html")
#                         email.send()
                        
#                         messages.success(request, f"Please check your email and verify your login attempt")
#                         return redirect("login_with_otp", username=username)

#                     else:
#                         messages.error(request, f"Email or password may be wrong!")
#                         return render(request, "signin.html")


                    
#                 else:
#                     otp = OTP.objects.create(user=user, otp=random.randrange(100000, 999999), otp_expire=timezone.now() + timezone.timedelta(minutes=2))
                
#                     context = {
#                         'username':user.username,
#                         'otp':otp.otp,
#                     }

#                     html_content =  render_to_string(template_name="otp_email.html", context=context)

#                     subject="Email Verification"
#                     body = "Email from ADMIN"
#                     from_email = settings.DEFAULT_FROM_EMAIL
#                     to = [user.email,]
                
                
#                     # send email
#                     email = EmailMultiAlternatives(
#                             subject,
#                             body,
#                             from_email,
#                             to,
#                         )
#                     email.attach_alternative(html_content, "text/html")
#                     email.send()
#                     messages.success(request, f"Please check your email and verify")
#                     return redirect("verify_otp", user.username)

                
#             else:
#                 messages.warning(request, f"This email is not in our list!")
#                 return render(request, "signin.html")
            
#         return render(request, "signin.html")  


#     else:
#         messages.warning(request, f"You are already authenticated!")
#         return redirect("home")
    

    





# def login_with_otp(request, username):
#     if request.user.is_authenticated == False:

#         user = User.objects.get(username=username)
#         otp = OTP.objects.filter(user=user).last()
        
        
#         if request.method == 'POST':
#             # valid token
#             if otp.otp == request.POST['otp']:
                
#                 # checking for expired token
#                 if otp.otp_expire > timezone.now():
#                     user = get_object_or_404(User, username=user.username)    
#                     login(request, user)
#                     otp.delete()
#                     request.session['session_expirey'] = timezone.now().timestamp()
#                     messages.success(request, f"Hi {user.username}, you are now logged-in")
#                     return redirect("home")
#                 else:
#                     messages.error(request, f"Your OTP is no longer valid!")
#                     return redirect("login_with_otp", user.username)
#         return render(request, "login_with_otp.html")

#     else:
#         messages.warning(request, f"You are already authenticated!")
#         return redirect("home")
    






# def signout(request):
#     logout(request)
#     messages.success(request, "Logout successfully")
#     return redirect("signin")






# def forgot_password(request):
#     if request.user.is_authenticated == False:

#         if request.method == 'POST':
             
#             ip = get_client_ip(request)
#             email = request.POST['email']
            
#             if User.objects.filter(email=email).exists():
#                 user = User.objects.get(email=email)
#                 uid = urlsafe_base64_encode(force_bytes(user.pk))
#                 token = default_token_generator.make_token(user)
#                 reset_link = request.build_absolute_uri(f"/reset-password/{uid}/{token}/")

#                 context = {
#                     'username':user.username,
#                     'reset_link':reset_link,
#                     'ip': f"Someone trying to reset your password from this address - {ip}. If it's your attempt then apply the link.",
#                 }

#                 html_content =  render_to_string(template_name="pass_reset_email.html", context=context)

#                 subject="Reset Your Password"
#                 body = "Email from ADMIN"
#                 from_email = settings.DEFAULT_FROM_EMAIL
#                 to = [user.email,]
            
            
#                 # send email
#                 email = EmailMultiAlternatives(
#                         subject,
#                         body,
#                         from_email,
#                         to,
#                     )
#                 email.attach_alternative(html_content, "text/html")
#                 email.send()
#                 messages.success(request, f"Please check your email and click the link to reset your password")
#                 return render(request, "forgot_password.html")
            
#             else:
#                 messages.error(request, f"User does not found!")
#                 return render(request, "forgot_password.html")
            
#         return render(request, "forgot_password.html")
    
#     else:
#         messages.warning(request, f"You are already authenticated!")
#         return redirect("home")








# def reset_password(request, uidb64, token):
#     if request.user.is_authenticated == False:

#         token_generator = TokenGenerator(expiry_minutes=2)

#         try:
#             uid = force_bytes(urlsafe_base64_decode(uidb64))
#             user = User.objects.get(pk=uid)
#         except(User.DoesNotExist, ValueError, TabError):
#             user = None

#         if user and token_generator.check_token(user, token):
#             if request.method == 'POST':
#                 new_pass1 = request.POST['new_pass1']
#                 new_pass2 = request.POST['new_pass2']

#                 if new_pass1 == new_pass2:
#                     user.set_password(new_pass1)
#                     user.save()
#                     messages.success(request, f"Your password reset successfully")
#                     return redirect("signin")
#                 else:
#                     messages.error(request, f"Password does not match!")
#                     return render(request, "reset_password.html")

#         else:
#             messages.error(request, f"User does not found or token has expired")
#             return redirect("forgot_password")
        
#         return render(request, "reset_password.html")

#     else:
#         messages.warning(request, f"You are already authenticated!")
#         return redirect("home")






# def change_pass(request):
#     if request.user.is_authenticated:
#         if request.method == 'POST':
#             user = request.user
#             old_password = request.POST.get('old_password')
#             new_password = request.POST.get('new_password')
#             new_password2 = request.POST.get('new_password2')

#             if user.check_password(old_password):
#                 if new_password == new_password2:
#                     user.set_password(new_password)
#                     user.save()
#                     update_session_auth_hash(request, user)
#                     messages.success(request, "Password changed successfully")
#                     return redirect("home") 
#                 else:
#                     messages.error(request, "Passwords do not match!")
#                     return render(request, "change_pass.html")
#             else:
#                 messages.error(request, "Old password is not correct!")
#                 return render(request, "change_pass.html")

#         # This line handles GET requests
#         return render(request, "change_pass.html")

#     else:
#         messages.warning(request, "You are unauthenticated!")
#         return redirect("signin")



# # -----------------------------------
# # ✅ Admin Login & Key Verify System
# # -----------------------------------

# def admin_login(request):
#     if not request.user.is_authenticated:
#         if request.method == 'POST':
#             email = request.POST.get('email')
#             password = request.POST.get('password')

#             user = authenticate(request, username=email, password=password)
#             if user and user.is_staff:
#                 request.session['admin_logging'] = True
#                 request.session['admin_user'] = user.username
#                 messages.success(request, "Admin identity approved, now enter the key to access your dashboard")
#                 return redirect("key_verify")
#             else:
#                 messages.error(request, "You are not admin!")
#                 return redirect("admin_login")
#         return render(request, "admin_login.html")

#     messages.warning(request, "You are already in session!")
#     return redirect("admin:index")


# def key_verify(request):
#     if request.session.get('admin_logging'):
#         username = request.session.get('admin_user')
#         user = get_object_or_404(User, username=username)

#         if request.method == 'POST':
#             key = request.POST.get('key')
#             if key == "admin123" and user.is_staff:
#                 login(request, user)
#                 request.session.pop('admin_logging', None)
#                 request.session.cycle_key()
#                 messages.success(request, "Admin logged-in successfully")
#                 return redirect('admin:index')
#             else:
#                 messages.error(request, "You are not Admin or wrong key!")
#                 return redirect('key_verify')

#         return render(request, "key_verify.html")

#     return redirect('admin_login')





# def view_404(request, exception):
#     return render(request, '404.html', status=404)