# myapp/middleware.py
from django.contrib.auth import logout
from django.utils import timezone
from django.shortcuts import redirect
from django.contrib import messages

class InactivityLogoutMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.timeout = 600  # 10 minutes in seconds

    def __call__(self, request):
        if request.user.is_authenticated:
            last_activity = request.session.get('session_expirey')

            now = timezone.now().timestamp()
            if last_activity and (now - last_activity > self.timeout):
                logout(request)
                request.session.flush()  # clear session
                messages.warning(request, f"Your session has expired. Please login again to access your account!")
                return redirect("signin")
            else:
                # update last activity timestamp
                request.session['session_expirey'] = now

        response = self.get_response(request)
        return response
