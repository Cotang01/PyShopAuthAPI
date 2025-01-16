from rest_framework.exceptions import AuthenticationFailed

from django.contrib.auth import get_user_model
from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist

from datetime import datetime, timedelta, UTC
from constance import config
import jwt


def generate_access_token(user):
    payload = {
        'user_id': user.id,
        'token_type': 'access',
        'exp_date': (datetime.now(UTC) + timedelta(
            seconds=config.ACCESS_TOKEN_LIFETIME_SECONDS)).isoformat()
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')


def generate_refresh_token_payload(user):
    payload = {
        'user_id': user.id,
        'token_type': 'refresh',
        'exp_date': (datetime.now(UTC) + timedelta(
            days=config.REFRESH_TOKEN_LIFETIME_DAYS)).isoformat()
    }
    return payload


def delete_refresh_token_obj_by_user(model, user):
    model.objects.filter(user=user).delete()


def delete_refresh_token_obj_by_token(model, token):
    model.objects.get(token=token).delete()


def create_refresh_token_obj(model, payload, user):
    exp_date = payload['exp_date']
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')
    return model.objects.create(user=user, token=token, exp_date=exp_date)


def get_user_from_token(token):
    try:
        payload = jwt.decode(token,
                             settings.SECRET_KEY,
                             algorithms=['HS256'])
        if payload['token_type'] != 'access':
            raise AuthenticationFailed('Invalid token type')
        user_id = payload['user_id']
        user = get_user_model().objects.get(id=user_id)
        return user
    except jwt.ExpiredSignatureError:
        raise AuthenticationFailed('Token is expired.')
    except jwt.DecodeError:
        raise AuthenticationFailed('Token is invalid.')
    except ObjectDoesNotExist:
        raise AuthenticationFailed('User does not exist.')


def extract_token_from_auth_header(auth_header):
    if not auth_header or not auth_header.startswith('Bearer '):
        return None
    return auth_header.replace('Bearer ', '')
