from django.urls import path

from signaling.views import healthz

urlpatterns = [
    path("healthz", healthz, name="healthz"),
]
