import unittest

from nanohttp import RestController, context, HttpBadRequest, json, settings

from restfulpy.authentication import StatefulAuthenticator
from restfulpy.client import Client
from restfulpy.controllers import RootController
from restfulpy.principal import JwtPrincipal, JwtRefreshToken
from restfulpy.testing.mockup import http_server
from restfulpy.tests.helpers import MockupApplication


class AuthController(RestController):
    @json
    def post(self):
        email = context.form.get('email')
        password = context.form.get('password')

        def bad():
            raise HttpBadRequest('Invalid email or password')

        if not (email and password):
            bad()

        principal = context.application.__authenticator__.login((email, password))
        if principal is None:
            bad()

        return dict(token=principal.dump().decode())


class Root(RootController):
    sessions = AuthController()


class MockupMember:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


class MockupServerAuthenticator(StatefulAuthenticator):
    def validate_credentials(self, credentials):
        email, password = credentials
        if email == 'user1@example.com' and password == '123456':
            return MockupMember(id=1, email=email, roles=['user'])

    def create_refresh_principal(self, member_id=None):
        return JwtRefreshToken(dict(id=member_id))

    def create_principal(self, member_id=None, session_id=None):
        return JwtPrincipal(dict(id=1, email='user1@example.com', roles=['user'], sessionId='1'))


class AuthClientTestCase(unittest.TestCase):
    mockup_application = MockupApplication('MockupApplication', Root(), authenticator=MockupServerAuthenticator())
    __configuration__ = '''
        db:
          uri: sqlite://    # In memory DB
          echo: false
        '''

    def setUp(self):
        super().setUp()
        self.mockup_application.configure(force=True)
        settings.merge(self.__configuration__)

    def test_auth_client(self):
        with http_server(self.mockup_application) as (server, url):
            client = Client(base_url=url)
            response = client.login({'email': 'user1@example.com', 'password': '123456'})

            self.assertIsNotNone(response.json()['token'])
            self.assertTrue(client.authenticator.authenticated)
            self.assertTrue(client.authenticator.is_in_roles('user'))


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
