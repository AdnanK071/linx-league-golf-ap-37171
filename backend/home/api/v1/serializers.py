from django.contrib.auth import get_user_model
from django.http import HttpRequest
from django.utils.translation import ugettext_lazy as _
from allauth.account import app_settings as allauth_settings
from allauth.account.forms import ResetPasswordForm
from allauth.utils import email_address_exists, generate_unique_username
from allauth.account.adapter import get_adapter
from allauth.account.utils import setup_user_email
from rest_framework import serializers
from rest_auth.serializers import PasswordResetSerializer
from rest_auth.models import TokenModel
from drf_writable_nested.serializers import WritableNestedModelSerializer
from django.contrib.auth import authenticate
from rest_framework import status

from users.models import Profile


User = get_user_model()


class SignupSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("id", "name", "email", "password")
        extra_kwargs = {
            "password": {"write_only": True, "style": {"input_type": "password"}},
            "email": {
                "required": True,
                "allow_blank": False,
            },
        }

    def _get_request(self):
        request = self.context.get("request")
        if (
            request
            and not isinstance(request, HttpRequest)
            and hasattr(request, "_request")
        ):
            request = request._request
        return request

    def validate_email(self, email):
        email = get_adapter().clean_email(email)
        if allauth_settings.UNIQUE_EMAIL:
            if email and email_address_exists(email):
                raise serializers.ValidationError(
                    _("A user is already registered with this e-mail address.")
                )
        return email

    def create(self, validated_data):
        user = User(
            email=validated_data.get("email"),
            name=validated_data.get("name"),
            username=generate_unique_username(
                [validated_data.get("name"), validated_data.get("email"), "user"]
            ),
        )
        user.set_password(validated_data.get("password"))
        user.save()
        request = self._get_request()
        setup_user_email(request, user, [])
        return user

    def save(self, request=None):
        """rest_auth passes request so we must override to accept it"""
        return super().save()


class UserSerializer2(serializers.ModelSerializer):
    profile = serializers.SerializerMethodField()

    def get_profile(self, obj):
        try:
            profile = Profile.objects.get(user=obj)
            return ProfileSerializer(profile).data
        except Exception as e:
            print(e)
            return None

    class Meta:
        model = User
        fields = ["id", "email", "name", "profile","first_name","last_name"]


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "email", "name","first_name","last_name"]


class PasswordSerializer(PasswordResetSerializer):
    """Custom serializer for rest_auth to solve reset password error"""

    password_reset_form_class = ResetPasswordForm


class UserProfileCreateSerializer(serializers.ModelSerializer):
    user = UserSerializer()

    class Meta:
        model = Profile
        fields = "__all__"

    def update(self, instance, validated_data):
        user = validated_data.pop("user", None)
        if user:
            try:
                _user = User.objects.get(id=instance.user.id)
                if "name" in user:
                    _user.name = user.get("name")
                if "last_name" in user:
                    _user.last_name = user.get("last_name")
                if "first_name" in user:
                    _user.first_name = user.get("first_name")
                _user.save()
                instance.user = _user
            except User.DoesNotExist:
                print("User does not exist")

        instance.save()
        instance = super().update(instance, validated_data)
        return instance


class UserFriendsSerializer(serializers.ModelSerializer):
    profile = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = [
            "id",
            "email",
            "name",
            "first_name",
            "last_name",
            "profile",
        ]

    def get_profile(self, obj):
        try:
            query = Profile.objects.get(user=obj)
        except Profile.DoesNotExist:
            return None
        return UserProfileCreateSerializer(query).data


class ProfileSerializer(serializers.ModelSerializer):

    friends = UserFriendsSerializer(
        many=True,
    )

    class Meta:
        model = Profile
        fields = "__all__"


class UserProfileSerializer(serializers.ModelSerializer):
    user = UserSerializer()
    friends = UserFriendsSerializer(
        many=True,
    )

    class Meta:
        model = Profile
        fields = "__all__"
        depth = 2

    def create(self, validated_data):
        # breakpoint()
        instance = super().create(validated_data)
        return instance

    def update(self, instance, validated_data):
        user = validated_data.pop("user", None)
        if user:
            try:
                _user = User.objects.get(id=instance.user.id)
                if "name" in user:
                    _user.name = user.get("name")
                if "last_name" in user:
                    _user.last_name = user.get("last_name")
                if "first_name" in user:
                    _user.first_name = user.get("first_name")
                _user.save()
                instance.user = _user
            except User.DoesNotExist:
                print("User does not exist")

        instance.save()
        instance = super().update(instance, validated_data)
        return instance


class TokenSerializer(serializers.ModelSerializer):
    """
    Serializer for Token model.
    """

    user = UserSerializer(read_only=True)
    profile = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = TokenModel
        fields = ("key", "user", "profile")

    def get_profile(self, obj):
        try:
            query = Profile.objects.get(user=obj.user)
        except Profile.DoesNotExist:
            return None
        return UserProfileSerializer(query).data

class AuthTokenSerializer(serializers.Serializer):
    email = serializers.CharField(label=_("Email"), write_only=True)
    password = serializers.CharField(
        label=_("Password"),
        style={"input_type": "password"},
        trim_whitespace=False,
        write_only=True,
    )
    token = serializers.CharField(label=_("Token"), read_only=True)
    def validate(self, attrs):
        email = attrs.get("email")
        password = attrs.get("password")
        if email and password:
            user = authenticate(
                request=self.context.get("request"), email=email, password=password
            )
            if not user:
                msg = _("Unable to log in with provided credentials.")
                error = {
                            "status": "error",
                            "code": status.HTTP_400_BAD_REQUEST,
                            "message": msg
                        }
                raise serializers.ValidationError(({'non_field_error': error}))
        else:
            msg = _('Must include "email" and "password".')
            raise serializers.ValidationError(msg, code="authorization")
        attrs["user"] = user
        return attrs


# Social Sign-In
from rest_auth.registration.serializers import SocialLoginSerializer, SocialConnectMixin
from rest_framework import serializers
from django.http import HttpRequest
from django.contrib.auth import get_user_model
from allauth.socialaccount.providers.oauth2.client import OAuth2Error
from allauth.socialaccount.helpers import complete_social_login
from allauth.account import app_settings as allauth_settings


class CustomAppleSocialLoginSerializer(SocialLoginSerializer):
    access_token = serializers.CharField(required=False, allow_blank=True)
    code = serializers.CharField(required=False, allow_blank=True)
    id_token = serializers.CharField(required=False, allow_blank=True)

    def _get_request(self):
        request = self.context.get("request")
        if not isinstance(request, HttpRequest):
            request = request._request
        return request

    def get_social_login(self, adapter, app, token, response):
        """
        :param adapter: allauth.socialaccount Adapter subclass.
            Usually OAuthAdapter or Auth2Adapter
        :param app: `allauth.socialaccount.SocialApp` instance
        :param token: `allauth.socialaccount.SocialToken` instance
        :param response: Provider's response for OAuth1. Not used in the
        :returns: A populated instance of the
            `allauth.socialaccount.SocialLoginView` instance
        """
        request = self._get_request()
        social_login = adapter.complete_login(request, app, token, response=response)
        social_login.token = token
        return social_login

    def validate(self, attrs):
        view = self.context.get("view")
        request = self._get_request()

        if not view:
            raise serializers.ValidationError(
                "View is not defined, pass it as a context variable"
            )

        adapter_class = getattr(view, "adapter_class", None)
        if not adapter_class:
            raise serializers.ValidationError("Define adapter_class in view")

        adapter = adapter_class(request)
        app = adapter.get_provider().get_app(request)

        # More info on code vs access_token
        # http://stackoverflow.com/questions/8666316/facebook-oauth-2-0-code-and-token

        # Case 1: We received the access_token
        if attrs.get("access_token"):
            access_token = attrs.get("access_token")
            token = {"access_token": access_token}

        # Case 2: We received the authorization code
        elif attrs.get("code"):
            self.callback_url = getattr(view, "callback_url", None)
            self.client_class = getattr(view, "client_class", None)

            if not self.callback_url:
                raise serializers.ValidationError("Define callback_url in view")
            if not self.client_class:
                raise serializers.ValidationError("Define client_class in view")

            code = attrs.get("code")

            provider = adapter.get_provider()
            scope = provider.get_scope(request)
            client = self.client_class(
                request,
                app.client_id,
                app.secret,
                adapter.access_token_method,
                adapter.access_token_url,
                self.callback_url,
                scope,
                key=app.key,
                cert=app.cert,
            )
            token = client.get_access_token(code)
            access_token = token["access_token"]

        else:
            raise serializers.ValidationError(
                "Incorrect input. access_token or code is required."
            )

        # Custom changes introduced to handle apple login on allauth
        try:
            social_token = adapter.parse_token(
                {
                    "access_token": access_token,
                    "id_token": attrs.get("id_token"),  # For apple login
                }
            )
            social_token.app = app
        except OAuth2Error as err:
            raise serializers.ValidationError(str(err)) from err

        try:
            login = self.get_social_login(adapter, app, social_token, access_token)
            complete_social_login(request, login)
        except HTTPError:
            raise serializers.ValidationError("Incorrect value")

        if not login.is_existing:
            # We have an account already signed up in a different flow
            # with the same email address: raise an exception, for security reasons.
            # If you decide to follow up with this flow, checkout allauth implementation:
            # add login.connect(request, email_address.user)
            # https://github.com/pennersr/django-allauth/issues/1149
            #
            # if allauth_settings.UNIQUE_EMAIL:
            #     # Do we have an account already with this email address?
            #     if get_user_model().objects.filter(email=login.user.email).exists():
            #         raise serializers.ValidationError(
            #             'E-mail already registered using different signup method.')

            login.lookup()
            login.save(request, connect=True)

        attrs["user"] = login.account.user
        return attrs


class CustomAppleConnectSerializer(
    SocialConnectMixin, CustomAppleSocialLoginSerializer
):
    pass
