#!/usr/bin/env python

import os
import sys

AUTHENTICATION_METHOD = 'Basic'

def environ_path_add(dirs, key='PATH'):
    """For each dir_ in dirs, prepend dir_ to the PATH environment variable.

    If key is specified, prepend dir_ to the named environment variable instead
    of PATH.

    """

    paths_str = os.getenv(key, '') 
    # ''.split(os.pathsep) gives ['']
    if paths_str.strip():
        paths = paths_str.split(os.pathsep)
    else:
        paths = []
    for dir_ in dirs:
        while dir_ in paths:
            paths.remove(dir_)
        paths.insert(0, dir_)
    os.environ[key] = os.pathsep.join(paths)

dir_lib = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
environ_path_add([dir_lib], 'PYTHONPATH')

CLIENT_FORGET_SEC = 60
CLIENT_ID_MIN_REPORT_RATE = 1.0  # 1 Hz
CLIENT_ID_REPORT_SECONDS = 3600  # Report every 1 hour.
LOG_COMMAND_TMPL = '[client-command] %s %s@%s:%s %s'
LOG_IDENTIFY_TMPL = '[client-identify] %d id requests in PT%dS'
LOG_FORGET_TMPL = '[client-forget] %s'
LOG_CONNECT_ALLOWED_TMPL = "[client-connect] %s@%s:%s privilege='%s' %s"

NO_PASSPHRASE = 'the quick brown fox'

CONNECT_DENIED_PRIV_TMPL = (
    "[client-connect] DENIED (privilege '%s' < '%s') %s@%s:%s %s")

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


user_priv = {
    'anonymous': 'identity',
    'cortex': 'full-control'
}

users = { 
    'cortex': 'lemon',
    'anonymous': 'default'
}


