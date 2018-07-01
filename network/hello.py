#!/usr/bin/env python

from gevent import pywsgi

import errno
import os
import socket
import random
import binascii
import inspect
from uuid import uuid4
from functools import wraps
from hashlib import md5, sha1
from time import time

from flask import Flask, session, g, url_for, render_template, Markup, request, redirect, send_from_directory, escape, jsonify
#from flask_session import Session

from network import (
    user_priv, AUTHENTICATION_TYPE, CLIENT_FORGET_SEC, CLIENT_ID_MIN_REPORT_RATE,
    CLIENT_ID_REPORT_SECONDS, LOG_COMMAND_TMPL, LOG_IDENTIFY_TMPL,
    LOG_FORGET_TMPL, LOG_CONNECT_ALLOWED_TMPL, NO_PASSPHRASE,
    PRIVILEGE_LEVELS, PRIV_IDENTITY, PRIV_DESCRIPTION, PRIV_STATE_TOTALS,
    PRIV_FULL_READ, PRIV_SHUTDOWN, PRIV_FULL_CONTROL, CONNECT_DENIED_PRIV_TMPL)

from OpenSSL import crypto
from werkzeug.utils import secure_filename

comms_options = 'md5'

if AUTHENTICATION_TYPE == 'Basic':
    from flask_httpauth import HTTPBasicAuth
    auth = HTTPBasicAuth()
elif AUTHENTICATION_TYPE == 'Digest':
    from flask_httpauth import HTTPDigestAuth
    auth = HTTPDigestAuth(use_ha1_pw=True)

app_server = None

class InvalidUsage(Exception):
    status_code = 400 

    def __init__(self, message, status_code=None, payload=None):
        Exception.__init__(self)
        self.message = message
        if status_code is not None:
            self.status_code = status_code
        self.payload = payload

    def to_dict(self):
        rv = dict(self.payload or ()) 
        rv['message'] = self.message
        return rv



def mkdir_p(path, mode=None):
    if mode:
        # reset mode and get current value
        old_mode = os.umask(0)

    try:
        if mode:
            os.makedirs(path, int(mode, 8))
        else:
            os.makedirs(path)

    except OSError, err:
        if err.errno != errno.EEXIST:
            raise
        else:
            # OK: path already exists
            pass

    if mode:
        os.umask(old_mode)

def _locate_item(item, path):
    """Locate a service item in "path"."""
    fname = os.path.join(path, item)
    if os.path.exists(fname):
        return fname

def _dump_item(path, item, value):
    """Dump "value" to a file called "item" in the directory "path".

    1. File permission should already be user-read-write-only on
       creation by mkstemp.
    2. The combination of os.fsync and os.rename should guarantee
       that we don't end up with an incomplete file.
    """
    mkdir_p(path)
    from tempfile import NamedTemporaryFile
    handle = NamedTemporaryFile(prefix=item, dir=path, delete=False)
    handle.write(value)
    os.fsync(handle.fileno())
    handle.close()
    fname = os.path.join(path, item)
    os.rename(handle.name, fname)
    print 'Generated %s' % fname


def _get_ssl_pem(path):
    file_name = _locate_item('ssl.pem', path)
    if file_name:
        return crypto.load_privatekey(
            crypto.FILETYPE_PEM, open(file_name).read())
    else:
        # Create a private key.
        pkey_obj = crypto.PKey()
        pkey_obj.generate_key(crypto.TYPE_RSA, 2048)
        _dump_item(
            path, 'ssl.pem',
            crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey_obj))
        return pkey_obj

def _get_ssl_cert(path, pkey_obj):
    """Load or create ssl.cert file for suite in path.

    Self-signed SSL certificate file.
    """
    # Use suite host as the 'common name', but no more than 64 chars.
    host = '127.0.0.1'
    common_name = host
    if len(common_name) > 64:
        common_name = common_name[:61] + "..."
    # See https://github.com/kennethreitz/requests/issues/2621
    ext = crypto.X509Extension(
        "subjectAltName",
        False,
        "DNS:%(dns)s, IP:%(ip)s, DNS:%(ip)s" % {
            "dns": host, "ip": host})
    file_name = _locate_item('ssl.cert', path)
    if file_name:
        cert_obj = crypto.load_certificate(
            crypto.FILETYPE_PEM, open(file_name).read())
        try:
            prev_ext = cert_obj.get_extension(0)
        except (AttributeError, IndexError):
            pass
        else:
            if (cert_obj.get_subject().CN == common_name and
                    not cert_obj.has_expired() and
                    str(prev_ext) == str(ext)):
                return  # certificate good for the same suite and host
    # Generate a new certificate
    cert_obj = crypto.X509()
    # cert_obj.get_subject().O = "Cylc"
    cert_obj.get_subject().CN = common_name
    cert_obj.gmtime_adj_notBefore(0)
    cert_obj.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)  # 10 years.
    cert_obj.set_issuer(cert_obj.get_subject())
    cert_obj.set_pubkey(pkey_obj)
    cert_obj.set_serial_number(1)
    cert_obj.add_extensions([ext])
    cert_obj.sign(pkey_obj, 'sha256')
    _dump_item(
        path, 'ssl.cert',
        crypto.dump_certificate(crypto.FILETYPE_PEM, cert_obj))

    
def create_app(schd_obj):

    app = Flask(__name__)

    #app.config['SESSION_TYPE'] = 'null'
    app.config['ENV'] = 'production'
    app.config['DEBUG'] = False
    app.config['SCHEDULER'] = schd_obj
    app.config['UPLOAD_FOLDER'] = '/home/sutherlanddw/projects/learn_flask/helloworld/uploads'
    app.config['SECRET_KEY'] = binascii.hexlify(os.urandom(16))
    app.config['JSONIFY_PRETTYPRINT_REGULAR'] = False
    
    ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'gz'])
    srv_d = '/home/sutherlanddw/projects/learn_flask/cylctest'


    def _set_users():
        users = { 
                'cortex': 'lemon',
                'anon': NO_PASSPHRASE
            }   
        if AUTHENTICATION_TYPE == 'Basic':
            for username in users:
                if "SHA1" in comms_options:
                    # Note 'SHA1' not 'SHA'.
                    users[username] = sha1(users.get(username)).hexdigest()
                else:
                    users[username] = md5(users.get(username)).hexdigest()
        return users
    
    
    users = _set_users()
    
    if AUTHENTICATION_TYPE == 'Basic':
        @auth.get_password
        def get_pw(username):
            if username in users:
                return users.get(username)
            return None
    
        @auth.hash_password
        def hash_pw(password):
            comms_options = 'md5'
            if "SHA1" in comms_options:
                # Note 'SHA1' not 'SHA'.
                return sha1(password).hexdigest()
            else:
                return md5(password).hexdigest()

    elif AUTHENTICATION_TYPE == 'Digest':
        @auth.get_password
        def get_pw(username):
            if username in users:
                return auth.generate_ha1(username,users.get(username))
                #return users.get(username)
            return None

    # Load or create SSL private key for the suite.
    pkey_obj = _get_ssl_pem(srv_d)
    # Load or create SSL certificate for the suite.
    _get_ssl_cert(srv_d, pkey_obj)    
    
    @app.errorhandler(InvalidUsage)
    def handle_invalid_usage(error):
        response = jsonify(error.to_dict())
        response.status_code = error.status_code
        return response

    api_endpoints(app)
    for vfunc in app.view_functions:
        app.add_url_rule('/id/'+vfunc, vfunc, app.view_functions[vfunc])

    test_endpoints(app)
    #api_endpoints(app,url_prefix='/id')

    @app.after_request
    def after_request(response):
        connection_denied = False
        if "Authorization" not in request.headers:
            # Probably just the initial HTTPS handshake.
            connection_denied = False
        elif isinstance(response.status, basestring):
            connection_denied = response.status.split()[0] in ["401", "403"]
        else:
            connection_denied = response.status in [401, 403]
        if connection_denied:
            print "Warning: Loging a connection denied Warning!"
        return response

    return app

def start_app(app):
    host = '127.0.0.1'
    flask_options = {'host': host}
    #flask_options['threaded'] = True


    srv_d = '/home/sutherlanddw/projects/learn_flask/helloworld'
    
    # set COMMS method
    comms_method = 'https'
    if comms_method == 'http':
        context = None
    else:
        context = (os.path.join(srv_d,'ssl.cert'),
            os.path.join(srv_d,'ssl.pem'))
        flask_options['ssl_context'] = context

    # Figure out the ports we are allowed to use.
    base_port = 5002
    max_ports = 2
    ok_ports = range(int(base_port), int(base_port) + int(max_ports))

    random.shuffle(ok_ports)

    # Check on specified host for free port
    for port in ok_ports:
        sock_check = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock_check.settimeout(1)
            sock_check.connect((flask_options['host'],port))
            sock_check.close()
        except socket.error:
            #host:port not in use
            flask_options['port'] = port
            try:
                #app.run(**flask_options)
                global app_server
                if comms_method == 'http':
                    app_server = pywsgi.WSGIServer((host, port), app)
                    srv_start_msg = "Server started: http://%s:%s"
                else:
                    app_server = pywsgi.WSGIServer((host, port), app,
                        certfile=context[0], keyfile=context[1])#,
                        #ca_certs='/etc/pki/tls/certs/ca-bundle.crt', cert_reqs=ssl.CERT_REQUIRED)
                    srv_start_msg = "Server started: https://%s:%s"

                app_server.start()
                print srv_start_msg % (host,port)
                break
            except socket.error:
                print "Unable to start api on port %s" % port
        
        if port == ok_ports[-1]:
            raise Exception("No available ports")

def shutdown_server():
    """Shutdown the web server."""
    if hasattr(app_server, "stop"):
        app_server.stop()

def get_port():
    """Return the web server port."""
    if hasattr(app_server, "server_port"):
        return app_server.server_port

# ** Client info and privilege checking
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



# Client sessions, 'time' is time of latest visit.
# Some methods may store extra info to the client session dict.
# {UUID: {'time': TIME, ...}, ...}
clients = {}
# Start of id requests measurement
_id_start_time = time()
# Number of client id requests
_num_id_requests = 0




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

def _check_access_priv_and_report(required_privilege_level, command, log_info=True):
    """Check access privilege and log requests with identifying info.

    In debug mode log all requests including task messages. Otherwise log
    all user commands, and just the first info command from each client.

    Return:
        dict: containing the client session

    """
    _check_access_priv(required_privilege_level)
    auth_user, prog_name, user, host, uuid = _get_client_info()
    priv_level = _get_priv_level(auth_user)
    #print(LOG_CONNECT_ALLOWED_TMPL % (
        #user, host, prog_name, priv_level, uuid))
    if uuid not in clients and log_info:
        #print(LOG_COMMAND_TMPL % (
        #    command, user, host, prog_name, uuid))
        pass
    clients.setdefault(uuid, {})
    clients[uuid]['time'] = time()
    _housekeep()
    return clients[uuid]


def _get_priv_level(auth_user):
    """Get the privilege level for this authenticated user."""
    if auth_user in user_priv:
        return user_priv.get(auth_user)
    return 'identity'
    #return self.schd.config.cfg['cylc']['authentication']['public']

def _report_id_requests():
    """Report the frequency of identification (scan) requests."""
    _num_id_requests += 1
    now = time()
    interval = now - _id_start_time
    if interval > CLIENT_ID_REPORT_SECONDS:
        rate = float(_num_id_requests) / interval
        log = None
        if rate > CLIENT_ID_MIN_REPORT_RATE:
            log = "warning"
        
        #print(LOG_IDENTIFY_TMPL % ( 
        #        _num_id_requests, interval ))
        _id_start_time = now 
        _num_id_requests = 0 
    uuid = _get_client_info()[4]
    clients.setdefault(uuid, {}) 
    clients[uuid]['time'] = now 
    _housekeep()
   

def _housekeep():
    """Forget inactive clients."""
    for uuid, client_info in clients.copy().items():
        if time() - client_info['time'] > CLIENT_FORGET_SEC:
            try:
                del clients[uuid]
            except KeyError:
                pass
            print(LOG_FORGET_TMPL % uuid)


def _literal_eval(key, value, default=None):
    """Wrap ast.literal_eval if value is basestring.

    On SyntaxError or ValueError, return default is default is not None.
    Otherwise, raise HTTPError 400.
    """
    if isinstance(value, basestring):
        try:
            return ast.literal_eval(value)
        except (SyntaxError, ValueError):
            if default is not None:
                return default
            raise InvalidUsage(
                'Bad argument value: %s=%s' % (key, value),400)
    else:
        return value

def priv_check(privilege, log_info=True):
    def priv_decorator(func):
        @wraps(func)
        def priv_wrapper(*args, **kwargs):
            command = func.__name__
            _check_access_priv_and_report(privilege, command, log_info)
            return func(*args, **kwargs)
        return priv_wrapper
    return priv_decorator


def test_endpoints(app):
    @app.route('/test_func')
    def new_function():
        return "Hello!"


def api_endpoints(app, url_prefix=None):
    
    if url_prefix is None or url_prefix == '/':
        url_prefix = ''
    elif isinstance(url_prefix, basestring):
        if url_prefix[0] != '/':
            url_prefix = '/' + url_prefix

    schd = app.config['SCHEDULER']
    suite = schd.suite

    # ** End point definitions
    @app.route(url_prefix+'/schd_info')
    @auth.login_required
    @priv_check('identity')
    def schd_info():
        #print(suite)
        #auth_user = request.authorization.username
        api_dict = schd.about_api()
        api_dict['suite'] = suite
        return jsonify(api_dict)

    @app.route(url_prefix+'/print_auth')
    @auth.login_required
    @priv_check('identity')
    def print_auth():
        #auth_user = request.authorization.username
        headers = request.headers
        enviro = request.environ
        autho_type = headers['Authorization']
        client_info = _get_client_info()
        return jsonify(True,'''Hello: {0} {1}'''.format(client_info, headers))

    @app.route(url_prefix+'/print_elite', methods=['GET'])
    @auth.login_required
    @priv_check(PRIV_FULL_CONTROL, log_info=False)
    def print_auth2():
        #auth_user = request.authorization.username
        argone = request.args.get('argone')
        argtwo = request.args.get('argtwo')
        argthree = request.args.get('argthree')
        headers = request.headers
        enviro = request.environ
        autho_type = headers['Authorization']
        client_info = _get_client_info()
        return '''Hello: {0} {1}

{2}
{3}
{4}

'''.format(client_info, headers, argone, argtwo, argthree)

    @app.route(url_prefix+'/postjson', methods = ['GET', 'POST'])
    def postjson():
        if not request.is_json:
            raise InvalidUsage("Unsupported Content-Type: Must be JSON", status_code=415)
        check_syntax = True
        check_syntax = _literal_eval('check_syntax', check_syntax)
        print(check_syntax)
        req_data = request.get_json()
        greeting = req_data.get('greeting')
        name = req_data.get('name')
        return '''
{0} {1}
'''.format(greeting, name)


    @app.route(url_prefix+'/')
    @priv_check('identity')
    def index():
        #if 'username' in session:
        #    return 'Logged in as %s' % escape(session['username'])
        return 'You are not logged in'


    @app.route(url_prefix+'/hello/')
    @app.route(url_prefix+'/hello/<name>')
    def hello(name=None):
        return render_template('hello.html', name=name)

    @app.route(url_prefix+"/user/<username>")
    def show_user_profile(username):
        return 'User %s' % username

    @app.route(url_prefix+'/post/<int:post_id>/')
    def show_post(post_id):
        return 'Post %d' % post_id

    @app.route(url_prefix+'/inherit/')
    def inherit_template():
        return render_template('child_1.html')

#    @app.route(url_prefix+'/login', methods=['POST', 'GET'])
#    def login():
#        error = None
#        if request.method == 'POST':
#            if valid_login(request.form['username'],
#                           request.form['password']):
#                session['username'] = request.form['username']
#                return redirect(url_for('index'))
#            else:
#                error = 'Invalid username/password'
#        # the code below is executed if the request method
#        # was GET or the credentials were invalid
#        return render_template('login.html', error=error)

    def valid_login(username,password):
        if username in users and password == users.get(username):
            return True


#    @app.route(url_prefix+'/logout')
#    def logout():
#        # remove the username from the session if it's there
#        session.pop('username', None)
#        return redirect(url_for('index'))



    def allowed_file(filename):
        return '.' in filename and \
               filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

    @app.route(url_prefix+'/upload/', methods=['GET', 'POST'])
    def upload_file():
        error=None
        if request.method == 'POST':
            # check if the post request has the file part
            if 'file' not in request.files:
                flash('No file part')
                return redirect(request.url)
            file = request.files['file']
            # if user does not select file, browser also
            # submit a empty part without filename
            if file.filename == '':
                flash('No selected file')
                return redirect(request.url)
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                return redirect(url_for('file_uploaded',
                                        filename=filename))
        return render_template('upload.html', error=error)


    @app.route(url_prefix+'/uploaded/')
    def file_uploaded():
        return 'File uploaded'

    @app.route(url_prefix+'/uploads/<filename>')
    def uploaded_file(filename):
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

    @app.route(url_prefix+'/scheduler')
    def print_scheduler():
        return schd

    with app.test_request_context():
        print url_for('index')
        print url_for('hello', name='Andre the Giant')
        print url_for('show_user_profile', username='Bob Marley')
        print url_for('show_post', post_id=1224 )




if __name__ == "__main__":
    app = create_app()
    start_app(app)
