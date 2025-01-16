from django.utils.deprecation import MiddlewareMixin

from .utils.auth import extract_token_from_auth_header, get_user_from_token


class JWTAuthenticationMiddleware(MiddlewareMixin):
    def process_request(self, request):
        if token := extract_token_from_auth_header(
                request.META.get('Authorization')):
            return get_user_from_token(token), None
