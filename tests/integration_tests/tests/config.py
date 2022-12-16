import os

import requests

CLIENT_ID = os.environ.get("CLIENT_ID", "authen-wetrade")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET", "8cmSnToMMJ0yLDuAUbtV2YzpbW0r3Oz3")

KONG_API = os.environ.get("KONG_API", "http://10.90.10.206:8000")
KONG_ADMIN = os.environ.get("KONG_ADMIN", "http://10.90.10.206:8001")

KC_USER = os.environ.get("KC_USER", "viet.pc")
KC_PASS = os.environ.get("KC_PASS", "abc123")
KC_HOST = os.environ.get("KC_HOST", "http://10.90.10.206:8080")
KC_REALM = KC_HOST + "/realms/wetrade"

r = requests.post(KC_REALM + "/protocol/openid-connect/token", data={
    'grant_type': 'password',
    'client_id': 'admin-cli',
    'username': KC_USER,
    'password': KC_PASS
})

assert r.status_code == 200
KC_ADMIN_TOKEN = r.json()['access_token']

# r = requests.get(KC_HOST + '/admin/serverinfo', headers={'Authorization': 'Bearer ' + KC_ADMIN_TOKEN})
# assert r.status_code == 200
# KC_VERSION = r.json()['systemInfo']['version']
