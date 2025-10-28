"""
URL configuration for config project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.contrib.auth import views as login_views
from django.urls import path, include
from auth_app.views import *

urlpatterns = [
    path('author/', admin_login, name='admin_login'),
    path('author/verify-key/', key_verify, name='key_verify'),
    path('administration/login/', lambda request: redirect('admin_login')),
    path('administration/', admin.site.urls),
    path('', include('auth_app.urls'))
] + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
