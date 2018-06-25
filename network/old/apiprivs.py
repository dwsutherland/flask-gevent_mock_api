#!/usr/bin/env python

import os
from uuid import uuid4
from functools import wraps

from flask import request


user_priv = {
    'anonymous': 'identity',
    'cortex': 'full-read'
}

NO_PASSPHRASE = 'the quick brown fox'


# Ordered privilege levels for authenticated users.
PRIV_IDENTITY = 'identity'
PRIV_DESCRIPTION = 'description'
PRIV_STATE_TOTALS = 'state-totals'
PRIV_FULL_READ = 'full-read'
PRIV_SHUTDOWN = 'shutdown'
PRIV_FULL_CONTROL = 'full-control'
PRIVILEGE_LEVELS = [
    PRIV_IDENTITY,
    PRIV_DESCRIPTION,
    PRIV_STATE_TOTALS,
    PRIV_FULL_READ,
    PRIV_SHUTDOWN,  # (Not used yet - for the post-passhprase era.)
    PRIV_FULL_CONTROL,
]





CONNECT_DENIED_PRIV_TMPL = (
    "[client-connect] DENIED (privilege '%s' < '%s') %s@%s:%s %s")

def _get_client_info():
    """Return information about the most recent cherrypy request, if any."""
    if hasattr(request.authorization, 'username'):
        auth_user = request.authorization.username
    else:
        auth_user = 'Unknown'
    info = request.headers
    origin_string = info.get("User-Agent", "")
    origin_props = {}
    if origin_string:
        try:
            origin_props = dict(
                [_.split("/", 1) for _ in origin_string.split()]
            )
        except ValueError:
            pass
    prog_name = origin_props.get("prog_name", "Unknown")
    uuid = origin_props.get("uuid", uuid4())
    host = info.get("Host", "Unknown")
    if info.get("From") and "@" in info["From"]:
        user = info["From"].split("@")[0]
    else:
        user = ("Unknown")
    return auth_user, prog_name, user, host, uuid


def _access_priv_ok(required_privilege_level):
    """Return True if a client is allowed access to info from server_obj.

    The required privilege level is compared to the level granted to the
    client by the connection validator (held in thread local storage).

    """
    try:
        return _check_access_priv(required_privilege_level)
    except InvalidUsage:
        return False

def _check_access_priv(required_privilege_level):
    """Raise an exception if client privilege is insufficient for server_obj.

    (See the documentation above for the boolean version of this function).

    """
    auth_user, prog_name, user, host, uuid = _get_client_info()
    priv_level = _get_priv_level(auth_user)
    if (PRIVILEGE_LEVELS.index(priv_level) <
            PRIVILEGE_LEVELS.index(required_privilege_level)):
        err = CONNECT_DENIED_PRIV_TMPL % (
            priv_level, required_privilege_level,
            user, host, prog_name, uuid)
        #LOG.warning(err)
        # Raise an exception to be sent back to the client.
        raise InvalidUsage(err, status_code=403)
    return True


def _get_priv_level(auth_user):
    """Get the privilege level for this authenticated user."""
    if auth_user in user_priv:
        return user_priv.get(auth_user)
    return 'identity'
    #return self.schd.config.cfg['cylc']['authentication']['public']



def priv_check(privilege):
    def priv_decorator(func):
        @wraps(func)
        def priv_wrapper(*args, **kwargs):
            _check_access_priv(privilege)
            return func(*args, **kwargs)
        return priv_wrapper
    return priv_decorator

