from django.urls import path, include
from rest_framework.routers import DefaultRouter

from home.api.v1.viewsets import *
from rest_auth.registration.views import (
    SocialAccountListView,
    SocialAccountDisconnectView,
)
router = DefaultRouter()
router.register("profile", UserProfileViewSet, basename="profile")
router.register("signup", SignupViewSet, basename="signup")
router.register("login", LoginViewSet, basename="login")


urlpatterns = [
    path("", include(router.urls)),
    path("get-user-profile/", UserProfileAPIView.as_view()),


     # login endpoints - used in social login
    path("facebook/login/", FacebookLogin.as_view(), name="social_facebook_login"),
    path("google/login/", GoogleLogin.as_view(), name="social_google_login"),
    path("apple/login/", AppleLogin.as_view(), name="social_apple_login"),
    # connect endpoints - can be used to implement connect to existing account
    path("facebook/connect/", FacebookLogin.as_view(), name="social_facebook_connect"),
    path("google/connect/", GoogleLogin.as_view(), name="social_google_connect"),
    path("apple/connect/", AppleLogin.as_view(), name="social_apple_connect"),
    path(
        "socialaccounts/", SocialAccountListView.as_view(), name="social_account_list"
    ),
    # Allows to disconnect social account
    path(
        "socialaccounts/<int:pk>/disconnect/",
        SocialAccountDisconnectView.as_view(),
        name="social_account_disconnect",
    ),
]
