from rest_framework.test import APIRequestFactory, force_authenticate
from rest_framework import status

from django.test import TestCase
from django.contrib.auth import get_user_model
from django.core.exceptions import ObjectDoesNotExist

from .models import RefreshToken
from .views import (
    RegistrationView,
    LoginView,
    AccessTokenRefreshView,
    LogoutView,
    MeView
)
from .utils.auth import (
    generate_refresh_token_payload,
    generate_access_token,
    create_refresh_token_obj
)

import json

User = get_user_model()


class UserRegistrationTests(TestCase):
    def setUp(self):
        self.factory = APIRequestFactory()
        self.register_url = "api/register/"
        self.user_data = {
            "password": "password",
            "email": "user@example.com"
        }

    def test_user_registration_success(self):
        request = self.factory.post(
            path=self.register_url,
            data=json.dumps(self.user_data),
            content_type='application/json'
        )
        response = RegistrationView.as_view()(request)
        user = User.objects.get(email=self.user_data['email'])

        self.assertEqual(user.email, self.user_data['email'])
        self.assertIn('id', response.data)
        self.assertIn('email', response.data)


class UserLoginTest(TestCase):
    def setUp(self):
        self.factory = APIRequestFactory()
        self.login_url = 'api/login/'
        self.user_data = {
            'password': 'password',
            'email': 'user@example.com'
        }
        self.user = User.objects.create_user(email='user@example.com',
                                             password='password')

    def test_user_login_success(self):
        login_request = self.factory.post(
            path=self.login_url,
            data=json.dumps(self.user_data),
            content_type='application/json'
        )
        login_response = LoginView.as_view()(login_request)
        self.assertIn('access_token', login_response.data)
        self.assertIn('refresh_token', login_response.data)


class UserLogoutTest(TestCase):
    def setUp(self):
        self.factory = APIRequestFactory()
        self.logout_url = 'api/logout/'
        self.user = User.objects.create_user(email='user@example.com',
                                             password='password')
        self.refresh_token_obj = create_refresh_token_obj(
            RefreshToken, generate_refresh_token_payload(self.user), self.user)
        force_authenticate(self.factory, self.user)

    def test_user_logout_success_and_token_deleted(self):
        request = self.factory.post(
            path=self.logout_url,
            data=json.dumps({'refresh_token': self.refresh_token_obj.token}),
            content_type='application/json')
        logout_response = LogoutView.as_view()(request)
        self.assertEqual(logout_response.status_code, status.HTTP_200_OK)
        with self.assertRaises(ObjectDoesNotExist):
            RefreshToken.objects.get(user=self.user)


class AccessTokenRefreshTest(TestCase):
    def setUp(self):
        self.factory = APIRequestFactory()
        self.token_refresh_url = "api/refresh/"
        self.user = User.objects.create_user(email='user@example.com',
                                             password='password')
        self.refresh_token_obj = create_refresh_token_obj(
            RefreshToken, generate_refresh_token_payload(self.user), self.user)

    def test_access_token_refresh_success(self):
        request = self.factory.post(
            path=self.token_refresh_url,
            data=json.dumps({'refresh_token': self.refresh_token_obj.token}),
            content_type='application/json')
        response = AccessTokenRefreshView.as_view()(request)
        data = response.data
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access_token', data)
        self.assertIn('refresh_token', data)
        RefreshToken.objects.get(token=response.data['refresh_token'])


class MeViewTest(TestCase):
    def setUp(self):
        self.factory = APIRequestFactory()
        self.me_url = 'api/me/'
        self.user = User.objects.create_user(email='user@example.com',
                                             password='password')
        self.access_token = generate_access_token(user=self.user)
        self.auth_header = f'Bearer {self.access_token}'

    def test_get_personal_data_success(self):
        request = self.factory.get(self.me_url)
        force_authenticate(request, self.user)
        request.META['Authorization'] = self.auth_header
        response = MeView.as_view()(request)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        data = response.data

        self.assertIn('id', data)
        self.assertEqual(data['id'], 1)
        self.assertIn('username', data)
        self.assertEqual(data['username'], '')
        self.assertIn('email', data)
        self.assertEqual(data['email'], 'user@example.com')

    def test_change_username_success(self):
        new_username_data = {'username': 'TestTest'}
        request = self.factory.put(self.me_url, new_username_data)
        force_authenticate(request, self.user)
        request.META['Authorization'] = self.auth_header
        response = MeView.as_view()(request)
        data = response.data
        self.assertIn('id', data)
        self.assertIn('username', data)
        self.assertIn('email', data)
        self.assertEqual('TestTest', data['username'])
