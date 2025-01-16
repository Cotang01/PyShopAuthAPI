from drf_spectacular.views import SpectacularSwaggerView, SpectacularRedocView, \
    SpectacularAPIView

from django.urls import path, include

from .views import (
    APIRoot,
    RegistrationView,
    LoginView,
    AccessTokenRefreshView,
    LogoutView,
    MeView,
    DocsView,
)

doc_patterns = [
    path('', SpectacularAPIView.as_view(), name='schema'),
    path('swagger-ui/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
    path('redoc/', SpectacularRedocView.as_view(url_name='schema'), name='redoc'),
]

urlpatterns = [
    path('', APIRoot.as_view(), name='api'),
    path('register/', RegistrationView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('refresh/', AccessTokenRefreshView.as_view(), name='refresh'),
    path('me/', MeView.as_view(), name='me'),
    path('docs/', DocsView.as_view(), name='docs'),
    path('schema/', include(doc_patterns), name='schema')
]
