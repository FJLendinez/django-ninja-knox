import base64
import json
from datetime import datetime, timedelta

from django.contrib.auth import get_user_model
from django.test import override_settings, TestCase, RequestFactory
from django.utils.timezone import now

from knox import auth, views
from knox.auth import KnoxAuth
from knox.models import AuthToken
from knox.signals import token_expired

User = get_user_model()


class AuthTestCase(TestCase):

    def setUp(self):
        self.username = 'john.doe'
        self.email = 'john.doe@example.com'
        self.password = 'hunter2'
        self.user = User.objects.create_user(self.username, self.email, self.password)

        self.username2 = 'jane.doe'
        self.email2 = 'jane.doe@example.com'
        self.password2 = 'hunter2'
        self.user2 = User.objects.create_user(self.username2, self.email2, self.password2)

    def test_login_creates_keys(self):
        self.assertEqual(AuthToken.objects.count(), 0)
        url = "/api/login/"
        body = {User.USERNAME_FIELD: "john.doe",
                "password": "hunter2"}
        for _ in range(5):
            response = self.client.post(url, body, content_type="application/json")
        self.assertEqual(AuthToken.objects.count(), 5)
        self.assertTrue(all(e.token_key for e in AuthToken.objects.all()))

    def test_login_returns_serialized_token(self):
        self.assertEqual(AuthToken.objects.count(), 0)
        url = "/api/login/"
        body = {User.USERNAME_FIELD: "john.doe",
                "password": "hunter2"}
        response = self.client.post(url,  body, content_type="application/json")
        self.assertEqual(response.status_code, 200)
        self.assertIn('token', response.json())
        username_field = self.user.USERNAME_FIELD
        self.assertNotIn(username_field, response.json())

    def test_logout_deletes_keys(self):
        self.assertEqual(AuthToken.objects.count(), 0)
        for _ in range(2):
            instance, token = AuthToken.objects.create(user=self.user)
        self.assertEqual(AuthToken.objects.count(), 2)

        url = "/api/logout/"
        self.client.post(url, content_type="application/json", HTTP_AUTHORIZATION=token)
        self.assertEqual(AuthToken.objects.count(), 1,
                         'other tokens should remain after logout')

    def test_logout_all_deletes_keys(self):
        self.assertEqual(AuthToken.objects.count(), 0)
        for _ in range(10):
            instance, token = AuthToken.objects.create(user=self.user)
        self.assertEqual(AuthToken.objects.count(), 10)

        url = "/api/logoutall/"
        self.client.post(url, {}, content_type="application/json", HTTP_AUTHORIZATION=token)
        self.assertEqual(AuthToken.objects.count(), 0)

    def test_logout_all_deletes_only_targets_keys(self):
        self.assertEqual(AuthToken.objects.count(), 0)
        for _ in range(10):
            instance, token = AuthToken.objects.create(user=self.user)
            AuthToken.objects.create(user=self.user2)
        self.assertEqual(AuthToken.objects.count(), 20)

        url = "/api/logoutall/"
        self.client.post(url, {}, content_type="application/json", HTTP_AUTHORIZATION=token)
        self.assertEqual(AuthToken.objects.count(), 10,
                         'tokens from other users should not be affected by logout all')

    def test_expired_tokens_login_fails(self):
        self.assertEqual(AuthToken.objects.count(), 0)
        instance, token = AuthToken.objects.create(
            user=self.user, expiry=timedelta(seconds=0))
        response = self.client.get("/api/mock/", content_type="application/json", HTTP_AUTHORIZATION=token)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), {"detail": "Unauthorized"})

    def test_expired_tokens_deleted(self):
        self.assertEqual(AuthToken.objects.count(), 0)
        for _ in range(10):
            # 0 TTL gives an expired token
            instance, token = AuthToken.objects.create(
                user=self.user, expiry=timedelta(seconds=0))
        self.assertEqual(AuthToken.objects.count(), 10)

        # Attempting a single logout should delete all tokens
        url = "/api/logout/"
        self.client.post(url, content_type="application/json", HTTP_AUTHORIZATION=token)
        self.assertEqual(AuthToken.objects.count(), 0)

    def test_update_token_key(self):
        self.assertEqual(AuthToken.objects.count(), 0)
        instance, token = AuthToken.objects.create(self.user)
        rf = RequestFactory()
        request = rf.get('/')
        request.META = {'HTTP_AUTHORIZATION': '{}'.format(token)}
        auth_user = KnoxAuth().authenticate(request, token)
        self.assertEqual(
            self.user, auth_user
        )

    def test_authorization_header_empty(self):
        rf = RequestFactory()
        request = rf.get('/')
        request.META = {'HTTP_AUTHORIZATION': ''}
        self.assertEqual(KnoxAuth().authenticate(request, ''), None)

    def test_authorization_header_prefix_only(self):
        rf = RequestFactory()
        request = rf.get('/mock/')
        request.META = {'HTTP_AUTHORIZATION': 'Token'}
        auth_user = KnoxAuth().authenticate(request, 'Token')
        self.assertEqual(
            auth_user, None
        )

    def test_authorization_header_spaces_in_token_string(self):
        rf = RequestFactory()
        request = rf.get('/')
        request.META = {'HTTP_AUTHORIZATION': 'Token wordone wordtwo'}
        self.user = KnoxAuth().authenticate(request, 'Token wordone wordtwo')
        self.assertEqual(
            self.user, None
        )

    def test_expiry_signals(self):
        self.signal_was_called = False

        def handler(sender, username, **kwargs):
            self.signal_was_called = True

        token_expired.connect(handler)

        instance, token = AuthToken.objects.create(user=self.user, expiry=timedelta(0))
        self.client.get("/api/mock/", HTTP_AUTHORIZATION=token)
        self.assertTrue(self.signal_was_called)
