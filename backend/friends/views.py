from rest_framework import viewsets

from .models import Friend
from .serializers import CreateFriendSerializer, GetFriendSerializer


class FriendViewSet(viewsets.ModelViewSet):
    queryset = Friend.objects.all()
    filterset_fields = {
        "user__id": ["exact"],
    }

    def get_serializer_class(self):
        if self.request.method in ("PUT", "POST", "PATCH"):
            return CreateFriendSerializer
        else:
            return GetFriendSerializer
