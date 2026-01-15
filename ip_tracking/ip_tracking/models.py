# ip_tracking/models.py
from django.db import models


class RequestLog(models.Model):
    ip_address = models.GenericIPAddressField()
    path = models.CharField(max_length=255)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.ip_address} - {self.path} - {self.timestamp}"

# ip_tracking/middleware.py
from .models import RequestLog


class IPLoggingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Get client IP address
        ip_address = self.get_client_ip(request)

        # Log request data
        RequestLog.objects.create(
            ip_address=ip_address,
            path=request.path
        )

        response = self.get_response(request)
        return response

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0]
        return request.META.get('REMOTE_ADDR')

# settings.py
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',

    'ip_tracking.middleware.IPLoggingMiddleware',

    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

INSTALLED_APPS = [
    ...
    'ip_tracking',
]


python manage.py makemigrations ip_tracking
python manage.py migrate

pip install django-ipgeolocation

INSTALLED_APPS = [
    ...
    'ipgeolocation',
    'ip_tracking',
]

# ip_tracking/models.py
from django.db import models


class RequestLog(models.Model):
    ip_address = models.GenericIPAddressField()
    path = models.CharField(max_length=255)
    timestamp = models.DateTimeField(auto_now_add=True)

    country = models.CharField(max_length=100, blank=True, null=True)
    city = models.CharField(max_length=100, blank=True, null=True)

    def __str__(self):
        return f"{self.ip_address} - {self.path}"

# ip_tracking/middleware.py
from django.http import HttpResponseForbidden
from django.core.cache import cache
from ipgeolocation import IpGeolocation
from .models import RequestLog, BlockedIP


class IPLoggingMiddleware:
    CACHE_TIMEOUT = 60 * 60 * 24  # 24 hours

    def __init__(self, get_response):
        self.get_response = get_response
        self.geo = IpGeolocation()

    def __call__(self, request):
        ip_address = self.get_client_ip(request)

        # Block blacklisted IPs
        if BlockedIP.objects.filter(ip_address=ip_address).exists():
            return HttpResponseForbidden("Your IP address is blocked.")

        # Get geolocation (cached)
        geo_data = self.get_geolocation(ip_address)

        RequestLog.objects.create(
            ip_address=ip_address,
            path=request.path,
            country=geo_data.get("country"),
            city=geo_data.get("city"),
        )

        response = self.get_response(request)
        return response

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            return x_forwarded_for.split(",")[0].strip()
        return request.META.get("REMOTE_ADDR")

    def get_geolocation(self, ip_address):
        cache_key = f"geo:{ip_address}"
        cached_data = cache.get(cache_key)

        if cached_data:
            return cached_data

        try:
            location = self.geo.get(ip_address)
            geo_data = {
                "country": location.get("country_name"),
                "city": location.get("city"),
            }
        except Exception:
            geo_data = {"country": None, "city": None}

        cache.set(cache_key, geo_data, self.CACHE_TIMEOUT)
        return geo_data

# settings.py
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
    }
}

python manage.py makemigrations ip_tracking
python manage.py migrate


