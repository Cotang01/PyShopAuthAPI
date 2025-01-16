from django.contrib.auth.models import BaseUserManager


class AuthUserManager(BaseUserManager):
    def create_user(self, email, password, username='', **extra_fields):
        if not email:
            raise ValueError('Email is required.')
        user = self.model(email=self.normalize_email(email),
                          username=username,
                          **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password, username='', **extra_fields):
        extra_fields['is_staff'] = True
        extra_fields['is_superuser'] = True
        return self.create_user(email, password, username, **extra_fields)
