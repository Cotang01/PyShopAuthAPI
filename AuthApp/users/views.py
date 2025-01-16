from rest_framework.generics import GenericAPIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from rest_framework.reverse import reverse

from django.contrib.auth import authenticate, get_user_model
from django.core.exceptions import ObjectDoesNotExist

from .serializers import (
    RegisterSerializer,
    LoginSerializer,
    LogoutSerializer,
    ProfileSerializer,
    TokenRefreshSerializer,
    PlaceholderSerializer,
)
from .utils.auth import (
    generate_access_token,
    generate_refresh_token_payload,
    create_refresh_token_obj,
    delete_refresh_token_obj_by_token,
)
from .models import RefreshToken


class APIRoot(GenericAPIView):
    serializer_class = PlaceholderSerializer

    def get(self, request):
        return Response({
            'Register': reverse('register', request=request),
            'Login': reverse('login', request=request),
            'Logout': reverse('logout', request=request),
            'Me': reverse('me', request=request),
            'Docs': reverse('docs', request=request),
        })


class DocsView(GenericAPIView):
    serializer_class = PlaceholderSerializer

    def get(self, request):
        return Response({
            'Swagger': reverse('swagger-ui', request=request),
            'Redoc': reverse('redoc', request=request),
            'API Root': reverse('api', request=request)
        })


class RegistrationView(GenericAPIView):
    serializer_class = RegisterSerializer
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            return Response({
                'id': user.id,
                'email': user.email
            }, status=status.HTTP_201_CREATED)
        return Response({'error': 'Non unique email.'},
                        status=status.HTTP_400_BAD_REQUEST)


class LoginView(GenericAPIView):
    serializer_class = LoginSerializer
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            creds = serializer.validated_data
            user = authenticate(request,
                                username=creds['email'],
                                password=creds['password'])
            if not user:
                return Response({'error': 'Invalid credentials'},
                                status=status.HTTP_401_UNAUTHORIZED)
            access_token = generate_access_token(user=user)
            refresh_token_payload = generate_refresh_token_payload(user=user)

            refresh_token_obj = create_refresh_token_obj(
                RefreshToken, refresh_token_payload, user)
            response = Response({
                'access_token': access_token,
                'refresh_token': refresh_token_obj.token
            })
            # If we want to set access_token as cookie
            # access_token_payload = jwt.decode(access_token,
            #                      settings.SECRET_KEY,
            #                      algorithms=['HS256'])
            # response.set_cookie(
            #     'access_token', access_token,
            #     expires=access_token_payload['expire_date'],
            #     httponly=True, secure=True, samesite='strict')
            return response
        return Response(exception=serializer.errors,
                        status=status.HTTP_400_BAD_REQUEST)


class LogoutView(GenericAPIView):
    serializer_class = LogoutSerializer
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            try:
                refresh_token = serializer.validated_data['refresh_token']
                delete_refresh_token_obj_by_token(RefreshToken, refresh_token)
                return Response({'success': 'User logged out.'})
            except ObjectDoesNotExist as odne:
                return Response({'error': odne.__class__.__name__},
                                status=status.HTTP_400_BAD_REQUEST)
        return Response({'error': 'Invalid refresh token.'},
                        status=status.HTTP_400_BAD_REQUEST)


class AccessTokenRefreshView(GenericAPIView):
    serializer_class = TokenRefreshSerializer
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            try:
                old_refresh_token = serializer.validated_data['refresh_token']
                old_refresh_token_obj = RefreshToken.objects.get(
                    token=old_refresh_token)
                if not old_refresh_token_obj.is_valid():
                    return Response({'error': 'Refresh token is expired.'})
                user = old_refresh_token_obj.user
                new_access_token = generate_access_token(user=user)
                new_refresh_token_payload = generate_refresh_token_payload(user=user)
                new_refresh_token_obj = create_refresh_token_obj(
                    RefreshToken, new_refresh_token_payload, user)
                old_refresh_token_obj.delete()
                return Response({'access_token': new_access_token,
                                'refresh_token': new_refresh_token_obj.token},
                                status=status.HTTP_200_OK)
            except ObjectDoesNotExist as odne:
                return Response({'error': odne.__class__.__name__},
                                status=status.HTTP_400_BAD_REQUEST)


class MeView(GenericAPIView):
    serializer_class = ProfileSerializer
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        if not isinstance(user, get_user_model()):
            return Response({'error': 'Authorization required.'},
                            status=status.HTTP_401_UNAUTHORIZED)
        serializer = self.get_serializer(instance=user)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request):
        new_username = request.data.get('username')
        if new_username is None:
            Response({'error': 'New username required.'})
        user = request.user
        user.username = new_username
        user.save()
        return Response({'id': user.id, 'username': user.username,
                         'email': user.email}, status=status.HTTP_202_ACCEPTED)
