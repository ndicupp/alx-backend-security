# ip_tracking/models.py
from django.db import models


class SuspiciousIP(models.Model):
    ip_address = models.GenericIPAddressField()
    reason = models.TextField()
    flagged_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.ip_address} - {self.reason}"


# ip_tracking/tasks.py
from celery import shared_task
from django.utils import timezone
from datetime import timedelta

from .models import RequestLog, SuspiciousIP


SENSITIVE_PATHS = ["/admin", "/login"]
REQUEST_THRESHOLD = 100  # requests per hour


@shared_task
def detect_anomalous_ips():
    """
    Detect IPs with suspicious behavior:
    - More than 100 requests/hour
    - Access to sensitive paths
    """
    one_hour_ago = timezone.now() - timedelta(hours=1)

    # --- Rule 1: High request volume ---
    ip_counts = (
        RequestLog.objects
        .filter(timestamp__gte=one_hour_ago)
        .values("ip_address")
        .annotate(count=models.Count("id"))
        .filter(count__gt=REQUEST_THRESHOLD)
    )

    for entry in ip_counts:
        SuspiciousIP.objects.get_or_create(
            ip_address=entry["ip_address"],
            reason=f"Exceeded {REQUEST_THRESHOLD} requests/hour"
        )

    # --- Rule 2: Access to sensitive paths ---
    for path in SENSITIVE_PATHS:
        suspicious_logs = RequestLog.objects.filter(
            timestamp__gte=one_hour_ago,
            path__startswith=path
        ).values_list("ip_address", flat=True).distinct()

        for ip in suspicious_logs:
            SuspiciousIP.objects.get_or_create(
                ip_address=ip,
                reason=f"Accessed sensitive path: {path}"
            )

CELERY_BEAT_SCHEDULE = {
    'detect-anomalies-every-hour': {
        'task': 'ip_tracking.tasks.detect_ip_anomalies',
        'schedule': 3600.0,  # 3600 seconds = 1 hour
    },
}

#settings.py
from celery.schedules import crontab

CELERY_BEAT_SCHEDULE = {
    "detect-anomalous-ips-hourly": {
        "task": "ip_tracking.tasks.detect_anomalous_ips",
        "schedule": crontab(minute=0),  # every hour
    },
}


celery -A project_name worker -l info
celery -A project_name beat -l info

python manage.py makemigrations ip_tracking
python manage.py migrate


