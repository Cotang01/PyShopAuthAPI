from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.conf import settings
from django.utils import timezone

from .managers import AuthUserManager


class AuthUser(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(max_length=50, unique=True)
    username = models.CharField(max_length=50, blank=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)

    objects = AuthUserManager()
    USERNAME_FIELD = 'email'
    EMAIL_FIELD = 'email'

    def __str__(self):
        return f'User: {self.email} is_superuser: {self.is_superuser}'


class RefreshToken(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    token = models.CharField(max_length=255, unique=True)
    exp = models.DateTimeField()

    def is_valid(self):
        return self.exp > timezone.now()

    def __str__(self):
        return f'{self.user} up_to {self.exp}'
