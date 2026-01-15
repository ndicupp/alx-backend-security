pip install django-ratelimit

# settings.py
RATELIMIT_ENABLE = True
RATELIMIT_USE_CACHE = 'default'

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
    }
}

# ip_tracking/views.py
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from ratelimit.decorators import ratelimit


def login_view(request):
    return JsonResponse({"message": "Login endpoint"})

# ip_tracking/utils.py
def rate_limit_key(group, request):
    if request.user.is_authenticated:
        return "auth"
    return "anon"

# ip_tracking/views.py
from django.http import JsonResponse
from ratelimit.decorators import ratelimit
from .utils import rate_limit_key


@ratelimit(
    key='ip',
    rate='10/m',
    method='ALL',
    block=True
)
@ratelimit(
    key='ip',
    rate='5/m',
    method='ALL',
    block=True
)
def login_view(request):
    return JsonResponse({"message": "Login endpoint"})


# ip_tracking/urls.py
from django.urls import path
from .views import login_view

urlpatterns = [
    path("login/", login_view, name="login"),
]

path("ip/", include("ip_tracking.urls")),


