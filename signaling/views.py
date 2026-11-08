from django.http import HttpRequest, JsonResponse
from django.views.decorators.http import require_GET


@require_GET
def healthz(request: HttpRequest) -> JsonResponse:
    """Liveness check for the reverse proxy and uptime monitoring. Reveals nothing else."""
    return JsonResponse({"status": "ok"})
