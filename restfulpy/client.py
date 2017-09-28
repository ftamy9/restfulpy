import base64
from urllib.parse import urljoin

import requests
import ujson
from nanohttp import HttpStatus


class ClientAlreadyInitializedError(Exception):
    pass


class ClientNotInitializedError(Exception):
    pass


class ObjectProxy(object):
    """
    A simple object proxy to let deferred object's initialize later (for example: just after import):
    This class encapsulates some tricky codes to resolve the proxied object members using the
    `__getattribute__` and '__getattr__'. SO TAKE CARE about modifying the code, to prevent
    infinite loops and stack-overflow situations.

    Module: fancy_module

        deferred_object = None  # Will be initialized later.
        def init():
            global deferred_object
            deferred_object = AnyValue()
        proxy = ObjectProxy(lambda: deferred_object)

    In another module:

        from fancy_module import proxy, init
        def my_very_own_function():
            try:
                return proxy.any_attr_or_method()
            except: ObjectNotInitializedError:
                init()
                return my_very_own_function()

    """

    def __init__(self, resolver):
        object.__setattr__(self, '_resolver', resolver)

    @property
    def proxied_object(self):
        o = object.__getattribute__(self, '_resolver')()
        # if still is none, raise the exception
        if o is None:
            raise ClientNotInitializedError("Client is not initialized yet.")
        return o

    def __getattr__(self, key):
        if key.startswith('_'):
            return self.__dict__[key]
        return getattr(object.__getattribute__(self, 'proxied_object'), key)

    def __setattr__(self, key, value):
        if key.startswith('_'):
            self.__dict__[key] = value
            return
        setattr(object.__getattribute__(self, 'proxied_object'), key, value)


class DeferredHttpClient(ObjectProxy):
    _instance = None

    def __init__(self, backend_factory):
        super(DeferredHttpClient, self).__init__(
            self._get_instance
        )
        self._backend_factory = backend_factory

    def _get_instance(self):
        return self._instance

    def _set_instance(self, v):
        self._instance = v

    def initialize(self, force=False, **kw):
        instance = self._get_instance()
        if not force and instance is not None:
            raise ClientAlreadyInitializedError("Client is already initialized.")

        self._set_instance(self._backend_factory(**kw))


class AuthenticationRequiredError(Exception):
    pass


class LoginUnsuccessfulError(Exception):
    pass


class AlreadyAuthenticatedError(Exception):
    pass


class InMemoryStorage:
    def __init__(self):
        self._token = None

    def restore_token(self):
        return self._token

    def save_token(self, token):
        self._token = token

    def delete_token(self):
        self._token = None


class Authenticator:
    def __init__(
            self,
            token_request_header_key='Authorization',
            token_response_header_key='X-New-JWT-Token',
            storage=None
    ):
        self.token_request_header_key = token_request_header_key
        self.token_response_header_key = token_response_header_key
        self.storage = storage or InMemoryStorage()

        self._member = None

    @property
    def token(self):
        return self.storage.restore_token()

    @token.setter
    def token(self, token):
        if not self.token:
            self.delete_token()
        self.storage.save_token(token)
        self.member = self.extract_jwt_payload(token)

    def delete_token(self):
        self.storage.delete_token()
        self.member = None

    def restore_from_local_storage(self):
        token = self.token
        if token is None:
            return
        self._member = self.extract_jwt_payload(token)

    @property
    def member(self):
        if self._member is None:
            self.restore_from_local_storage()
        return self._member

    @member.setter
    def member(self, member):
        self._member = member

    def add_authentication_headers(self, request):
        if self.token is None:
            raise AuthenticationRequiredError()

        request.add_header(self.token_request_header_key, self.token)

    @classmethod
    def extract_jwt_payload(cls, jwt_token):
        decoded = base64.b64decode('%s=' % jwt_token.split('.')[1])  # To avoid padding exception
        payload = ujson.loads(decoded)
        return payload

    def is_in_roles(self, *roles):
        if not self.authenticated:
            raise AuthenticationRequiredError()
        if 'roles' in self.member:
            if set(self.member['roles']).intersection(roles):
                return True
        return False

    @property
    def authenticated(self):
        return self.member is not None

    def check_response(self, response):
        if response.headers.get(self.token_response_header_key, None):
            self.token = response.headers[self.token_response_header_key]
        else:
            raise LoginUnsuccessfulError()


class Request:
    def __init__(self, client, resource, verb, payload=None, query_string=None, headers=None, encoding='json'):
        self.client = client

        self.resource = resource
        self.verb = verb
        self.payload = payload if payload else {}
        self.query_strings = query_string if query_string else {}
        self.headers = headers if headers else {}
        # TODO: Implement the multipart and url-encoded
        self.encoding = encoding

    @property
    def url(self):
        return urljoin(self.client.base_url, self.resource)

    def add_authentication_headers(self, force=False):
        if self.client.authenticator.token:
            self.client.authenticator.add_authentication_headers(self)
        elif force:
            raise AuthenticationRequiredError()
        return self

    def add_parameter(self, key, value):
        self.payload.update({key: value})
        return self

    def add_parameters(self, parameters):
        self.payload.update(parameters)
        return self

    def add_query_string(self, key, value):
        # FIXME: Change it to list instead of dictionary
        self.query_strings.update({key: value})
        return self

    def add_header(self, key, value):
        self.headers.update({key: value})
        return self

    def filter(self, field, expression):
        self.add_query_string(field, expression)
        return self

    def take(self, take):
        self.add_query_string('take', take)
        return self

    def skip(self, skip):
        self.add_query_string('skip', skip)
        return self

    def sort(self, sort):
        self.add_query_string('sort', sort)
        return self

    def if_match(self, etag):
        self.headers['If-Match'] = etag
        return self

    def if_none_match(self, etag):
        self.headers['If-None-Match'] = etag
        return self

    def send(self):
        kwargs = {
            'allow_redirects': True,
            'headers': self.headers,
            'data': self.payload,
            'params': self.query_strings
        }

        response = requests.request(self.verb, self.url, **kwargs)

        if response.status_code != 200:
            exception = HttpStatus(
                response.reason,
                response.headers['x-reason'] if 'x-reason' in response.headers else None
            )
            exception.status_code = response.status_code
            if 'Content-Type' in response.headers and response.headers['Content-Type'] == 'application/json' and \
                    response.text:
                description = response.json()
                if 'message' in description:
                    exception.status_text = description['message']
                if 'description' in description:
                    exception.info = description['description']
            raise exception

        return response


class Model:
    pass


class Metadata:
    def __init__(self, models):
        self.models = models

    def load(self, client, entities):
        for entity in entities:
            client.request(url=entities)


class Client:
    __authenticator_factory__ = Authenticator
    _authenticator = None

    # TODO: Implement version compatibility checking
    __backend_compatibility__ = [
        (0, 27, 0),
        (0, 30, 0)
    ]

    def __init__(self, base_url, authenticator=None):
        self.base_url = base_url
        self._authenticator = authenticator

    @property
    def authenticator(self):
        if self._authenticator is None:
            self._authenticator = self.__authenticator_factory__()
        return self._authenticator

    def login(self, credentials=None):
        if self.authenticator.authenticated:
            raise AlreadyAuthenticatedError()

        request = self.request(resource='sessions', verb='POST', payload=credentials)

        try:
            response = request.send()
            self.authenticator.token = response.json().get('token', None)
            return response
        except HttpStatus as exception:
            self.authenticator.delete_token()
            raise exception

    def request(self, **kwargs):
        return Request(self, **kwargs)
