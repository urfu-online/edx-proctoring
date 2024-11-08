
""" Common Authentication Handlers used across projects. """

import logging

import django.utils.timezone
from oauth2_provider import models as dot_models
from provider.oauth2 import models as dop_models
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_oauth.authentication import OAuth2Authentication


OAUTH2_TOKEN_ERROR = u'token_error'
OAUTH2_TOKEN_ERROR_EXPIRED = u'token_expired'
OAUTH2_TOKEN_ERROR_MALFORMED = u'token_malformed'
OAUTH2_TOKEN_ERROR_NONEXISTENT = u'token_nonexistent'
OAUTH2_TOKEN_ERROR_NOT_PROVIDED = u'token_not_provided'


log = logging.getLogger(__name__)


class OAuth2AuthenticationEnforceActiveUser(OAuth2Authentication):
    """
    This authentication class ensures that the user is logged in and their account is active.
    This means that the user's is_active field must be True.
    """

    def authenticate(self, *args, **kwargs):
        """
        Returns two-tuple of (user, token) if access token authentication
        succeeds, raises an AuthenticationFailed (HTTP 401) if authentication
        fails or None if the user did not try to authenticate using an access
        token.
        """

        try:
            return super(OAuth2AuthenticationEnforceActiveUser, self).authenticate(*args, **kwargs)
        except AuthenticationFailed as exc:
            if isinstance(exc.detail, dict):
                developer_message = exc.detail['developer_message']
                error_code = exc.detail['error_code']
            else:
                developer_message = exc.detail
                if 'No credentials provided' in developer_message:
                    error_code = OAUTH2_TOKEN_ERROR_NOT_PROVIDED
                elif 'Token string should not contain spaces' in developer_message:
                    error_code = OAUTH2_TOKEN_ERROR_MALFORMED
                else:
                    error_code = OAUTH2_TOKEN_ERROR
            raise AuthenticationFailed({
                u'error_code': error_code,
                u'developer_message': developer_message
            })

    def authenticate_credentials(self, request, access_token):
        """
        Authenticate the request, given the access token.

        Ensures the user is active.
        """

        token = self.get_access_token(access_token)
        if not token:
            raise AuthenticationFailed({
                u'error_code': OAUTH2_TOKEN_ERROR_NONEXISTENT,
                u'developer_message': u'The provided access token does not match any valid tokens.'
            })
        elif token.expires < django.utils.timezone.now():
            raise AuthenticationFailed({
                u'error_code': OAUTH2_TOKEN_ERROR_EXPIRED,
                u'developer_message': u'The provided access token has expired and is no longer valid.',
            })
        elif not token.user.is_active:
            raise AuthenticationFailed({
                u'error_code': OAUTH2_TOKEN_ERROR,
                u'developer_message': u'The user associated with the access token is not active.',
            })
        else:
            return token.user, token

    def get_access_token(self, access_token):
        """
        Return a valid access token that exists in one of our OAuth2 libraries,
        or None if no matching token is found.
        """
        return self._get_dot_token(access_token) or self._get_dop_token(access_token)

    def _get_dop_token(self, access_token):
        """
        Return a valid access token stored by django-oauth2-provider (DOP), or
        None if no matching token is found.
        """
        token_query = dop_models.AccessToken.objects.select_related('user')
        return token_query.filter(token=access_token).first()

    def _get_dot_token(self, access_token):
        """
        Return a valid access token stored by django-oauth-toolkit (DOT), or
        None if no matching token is found.
        """
        token_query = dot_models.AccessToken.objects.select_related('user')
        return token_query.filter(token=access_token).first()