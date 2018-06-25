#!/usr/bin/env python


from flask_httpauth import HTTPDigestAuth

auth = HTTPDigestAuth()

users = {
    'cortex': 'lemon',
    'anonymous': 'default'
}

@auth.get_password
def get_pw(username):
    if username in users:
        return users.get(username)
    return None


