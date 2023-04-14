from rest_framework.viewsets import ModelViewSet, ViewSet
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.decorators import action

# Social Sign-In
from rest_framework.permissions import AllowAny
from allauth.socialaccount.providers.facebook.views import FacebookOAuth2Adapter
from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
from allauth.socialaccount.providers.oauth2.client import OAuth2Client
from allauth.socialaccount.providers.apple.views import AppleOAuth2Adapter
from allauth.socialaccount.providers.apple.client import AppleOAuth2Client
from rest_auth.registration.views import SocialLoginView, SocialConnectView
from .serializers import AuthTokenSerializer, CustomAppleSocialLoginSerializer, CustomAppleConnectSerializer
from django.contrib.sites.shortcuts import get_current_site

try:
    APP_DOMAIN = f"https://{get_current_site(None)}"
except Exception:
    APP_DOMAIN = ""


from home.api.v1.serializers import (
    SignupSerializer,
    UserSerializer2,
    UserProfileSerializer,
    UserProfileCreateSerializer,
)
from users.models import Profile


class UserProfileAPIView(APIView):
    def get(self, request):
        try:
            profile = Profile.objects.get(user=request.user)
            print(profile)
            profile_serializer = UserProfileSerializer(profile)
            return Response(data=profile_serializer.data)
        except Exception as e:
            print(e)
            return Response(status=status.HTTP_400_BAD_REQUEST)


class UserProfileViewSet(ModelViewSet):
    queryset = Profile.objects.all()
    lookup_field = "user__id"
    filterset_fields = ("user__id",)

    def get_serializer_class(self):
        if self.request.method in ("POST", "PUT", "PATCH"):
            return UserProfileCreateSerializer
        else:
            return UserProfileSerializer

    @action(detail=True, url_path="add-friend", methods=["POST"])
    def add_friend(self, request, user__id):
        try:
            profile = self.get_object()
            for p_id in request.data["p_ids"]:
                user_profile = Profile.objects.get(id=p_id)
                profile.friends.add(user_profile.user)
                user_profile.friends.add(profile.user)
            return Response(
                "Successfully friend added.", status=status.HTTP_201_CREATED
            )
        except Exception as e:
            print(e)
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, url_path="remove-friend", methods=["POST"])
    def remove_friend(self, request, user__id):
        try:
            profile = self.get_object()
            for p_id in request.data["p_ids"]:
                user_profile = Profile.objects.get(id=p_id)
                profile.friends.remove(user_profile.user)
            return Response(
                "Successfully friend added.", status=status.HTTP_201_CREATED
            )
        except Exception as e:
            print(e)
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


class SignupViewSet(ModelViewSet):
    serializer_class = SignupSerializer
    http_method_names = ["post"]


class LoginViewSet(ViewSet):
    """Based on rest_framework.authtoken.views.ObtainAuthToken"""

    serializer_class = AuthTokenSerializer

    def create(self, request):
        serializer = self.serializer_class(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data["user"]
        token, created = Token.objects.get_or_create(user=user)
        user_serializer = UserSerializer2(user)
        return Response({"token": token.key, "user": user_serializer.data})

# Social Sign-In
class FacebookLogin(SocialLoginView):
    permission_classes = (AllowAny,)
    adapter_class = FacebookOAuth2Adapter


class GoogleLogin(SocialLoginView):
    permission_classes = (AllowAny,)
    adapter_class = GoogleOAuth2Adapter
    client_class = OAuth2Client


class AppleLogin(SocialLoginView):
    adapter_class = AppleOAuth2Adapter
    client_class = AppleOAuth2Client
    serializer_class = CustomAppleSocialLoginSerializer
    callback_url = f"https://{APP_DOMAIN}/accounts/apple/login/callback/"


class FacebookConnect(SocialConnectView):
    permission_classes = (AllowAny,)
    adapter_class = FacebookOAuth2Adapter


class GoogleConnect(SocialConnectView):
    permission_classes = (AllowAny,)
    adapter_class = GoogleOAuth2Adapter
    client_class = OAuth2Client


class AppleConnect(SocialConnectView):
    adapter_class = AppleOAuth2Adapter
    client_class = AppleOAuth2Client
    serializer_class = CustomAppleConnectSerializer
