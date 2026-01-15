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

# ip_tracking/models.py
from django.db import models


class BlockedIP(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.ip_address

# ip_tracking/middleware.py
from django.http import HttpResponseForbidden
from .models import RequestLog, BlockedIP


class IPLoggingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip_address = self.get_client_ip(request)

        # Block request if IP is blacklisted
        if BlockedIP.objects.filter(ip_address=ip_address).exists():
            return HttpResponseForbidden("Your IP address is blocked.")

        # Log allowed requests
        RequestLog.objects.create(
            ip_address=ip_address,
            path=request.path
        )

        response = self.get_response(request)
        return response

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR')

ip_tracking/
 └── management/
     └── commands/
         └── block_ip.py


# ip_tracking/management/commands/block_ip.py
from django.core.management.base import BaseCommand
from ip_tracking.models import BlockedIP


class Command(BaseCommand):
    help = "Block an IP address"

    def add_arguments(self, parser):
        parser.add_argument("ip_address", type=str, help="IP address to block")

    def handle(self, *args, **options):
        ip_address = options["ip_address"]

        obj, created = BlockedIP.objects.get_or_create(ip_address=ip_address)

        if created:
            self.stdout.write(
                self.style.SUCCESS(f"IP address {ip_address} has been blocked.")
            )
        else:
            self.stdout.write(
                self.style.WARNING(f"IP address {ip_address} is already blocked.")
            )

python manage.py makemigrations ip_tracking
python manage.py migrate

python manage.py block_ip 192.168.1.10


