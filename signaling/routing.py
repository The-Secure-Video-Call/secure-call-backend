from django.urls import path

from signaling.consumers import SignalingConsumer

websocket_urlpatterns = [
    path("ws/signal/", SignalingConsumer.as_asgi()),
]
