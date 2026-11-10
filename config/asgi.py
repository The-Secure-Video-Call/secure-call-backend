"""ASGI entry point: plain HTTP goes to Django, WebSockets go to the signaling consumer.

Run with: daphne config.asgi:application
"""

import os

from django.core.asgi import get_asgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")

# Initialise Django before importing anything that touches models or settings.
django_asgi_app = get_asgi_application()

from channels.routing import ProtocolTypeRouter, URLRouter  # noqa: E402
from channels.security.websocket import OriginValidator  # noqa: E402
from django.conf import settings  # noqa: E402

from signaling.client_address import ClientAddressMiddleware  # noqa: E402
from signaling.routing import websocket_urlpatterns  # noqa: E402

application = ProtocolTypeRouter(
    {
        "http": django_asgi_app,
        # Reject WebSocket connections from any origin not explicitly allowed.
        "websocket": OriginValidator(
            # Adds scope["client_ip"] (the real client behind the trusted proxy) for rate limits.
            ClientAddressMiddleware(URLRouter(websocket_urlpatterns), settings.TRUSTED_PROXY_IPS),
            settings.SIGNALING_ALLOWED_ORIGINS,
        ),
    }
)
