from utils import *


class TestRoles(unittest.TestCase):

    @create_api({
        'allowed_iss': ['http://10.90.10.206:8080/auth/realms/wetrade']
    })
    @authenticate()
    @call_api()
    def test_no_auth(self, status, body):
        self.assertEqual(OK, status)

    @skip("Need to update tests")
    @create_api({
        'allowed_iss': ['http://10.90.10.206:8080/auth/realms/wetrade'],
        'roles': ['test_role']
    })
    @authenticate()
    @call_api()
    def test_roles_auth(self, status, body):
        if not KC_VERSION.startswith('3'):
            self.skipTest("Test not supported for " + KC_VERSION)
        self.assertEqual(OK, status)

    @create_api({
        'allowed_iss': ['http://10.90.10.206:8080/auth/realms/wetrade'],
        'roles': ['not_found']
    })
    @authenticate()
    @call_api()
    def test_roles_auth_rainy(self, status, body):
        self.assertEqual(FORBIDDEN, status)
        self.assertEqual('Access token does not have the required scope/role: Missing required role', body.get('message'))

    @skip("Need to update tests")
    @create_api({
        'allowed_iss': ['http://10.90.10.206:8080/auth/realms/wetrade'],
        'roles': ['test_role', 'not_found']
    })
    @authenticate()
    @call_api()
    def test_roles_auth_double(self, status, body):
        if not KC_VERSION.startswith('3'):
            self.skipTest("Test not supported for " + KC_VERSION)
        self.assertEqual(OK, status)

    @create_api({
        'allowed_iss': ['http://10.90.10.206:8080/auth/realms/wetrade'],
        'realm_roles': ['uma_authorization']
    })
    @authenticate()
    @call_api()
    def test_realm_roles_auth(self, status, body):
        self.assertEqual(OK, status)

    @create_api({
        'allowed_iss': ['http://10.90.10.206:8080/auth/realms/wetrade'],
        'realm_roles': ['not_found']
    })
    @authenticate()
    @call_api()
    def test_realm_roles_auth_rainy(self, status, body):
        self.assertEqual(FORBIDDEN, status)
        self.assertEqual('Access token does not have the required scope/role: Missing required realm role', body.get('message'))

    @create_api({
        'allowed_iss': ['http://10.90.10.206:8080/auth/realms/wetrade'],
        'realm_roles': ['uma_authorization', 'not_found']
    })
    @authenticate()
    @call_api()
    def test_realm_roles_auth_double(self, status, body):
        self.assertEqual(OK, status)

    @create_api({
        'allowed_iss': ['http://10.90.10.206:8080/auth/realms/wetrade'],
        'client_roles': ['account:manage-account']
    })
    @authenticate()
    @call_api()
    def test_client_roles_auth(self, status, body):
        self.assertEqual(OK, status)

    @create_api({
        'allowed_iss': ['http://10.90.10.206:8080/auth/realms/wetrade'],
        'client_roles': ['account:manage-something-else']
    })
    @authenticate()
    @call_api()
    def test_client_roles_auth_rainy(self, status, body):
        self.assertEqual(FORBIDDEN, status)
        self.assertEqual('Access token does not have the required scope/role: Missing required role', body.get('message'))

    @create_api({
        'allowed_iss': ['http://10.90.10.206:8080/auth/realms/wetrade'],
        'client_roles': ['account:manage-account', 'account:manage-something-else']
    })
    @authenticate()
    @call_api()
    def test_client_roles_auth_double(self, status, body):
        self.assertEqual(OK, status)

    @create_api({
        'allowed_iss': ['http://10.90.10.206:8080/auth/realms/wetrade'],
        'client_roles': ['user:do-user-stuff']
    })
    @authenticate()
    @call_api()
    def test_client_roles_auth(self, status, body):
        self.assertEqual(FORBIDDEN, status)
        self.assertEqual('Access token does not have the required scope/role: Missing required role', body.get('message'))

    @create_api({
        'allowed_iss': ['http://10.90.10.206:8080/auth/realms/wetrade'],
        'scope': ['email']
    })
    @authenticate()
    @call_api()
    def test_client_scope(self, status, body):
        if KC_VERSION.startswith('3'):
            self.skipTest("Test not supported for " + KC_VERSION)
        self.assertEqual(OK, status)

    @create_api({
        'allowed_iss': ['http://10.90.10.206:8080/auth/realms/wetrade'],
        'scope': ['email', 'not_found']
    })
    @authenticate()
    @call_api()
    def test_client_scope_double(self, status, body):
        if KC_VERSION.startswith('3'):
            self.skipTest("Test not supported for " + KC_VERSION)
        self.assertEqual(OK, status)

    @create_api({
        'allowed_iss': ['http://10.90.10.206:8080/auth/realms/wetrade'],
        'scope': ['not_found']
    })
    @authenticate()
    @call_api()
    def test_client_scope_rainy(self, status, body):
        self.assertEqual(FORBIDDEN, status)
        self.assertEqual('Access token does not have the required scope/role: Missing required scope', body.get('message'))
