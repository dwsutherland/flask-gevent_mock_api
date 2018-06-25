#!/usr/bin/env python


import os
from uuid import uuid4
from functools import wraps

from flask import url_for, render_template, Markup, request, redirect, send_from_directory, session, escape, jsonify

from apiauth import auth, users, get_pw

"""Suite runtime service API facade exposed via flask."""

CLIENT_FORGET_SEC = 60
CLIENT_ID_MIN_REPORT_RATE = 1.0  # 1 Hz
CLIENT_ID_REPORT_SECONDS = 3600  # Report every 1 hour.
LOG_COMMAND_TMPL = '[client-command] %s %s@%s:%s %s'
LOG_IDENTIFY_TMPL = '[client-identify] %d id requests in PT%dS'
LOG_FORGET_TMPL = '[client-forget] %s'
LOG_CONNECT_ALLOWED_TMPL = "[client-connect] %s@%s:%s privilege='%s' %s"


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


def apiendpoints(app):

    schd = app.config['SCHEDULER']

    @app.errorhandler(InvalidUsage)
    def handle_invalid_usage(error):
        response = jsonify(error.to_dict())
        response.status_code = error.status_code
        return response

    @app.route('/print_auth')
    @auth.login_required
    #@apiprivs.priv_check('identity')
    @priv_check('identity')
    def print_auth():
        #auth_user = request.authorization.username
        headers = request.headers
        enviro = request.environ
        autho_type = headers['Authorization']
        client_info = apiprivs._get_client_info()
        return '''Hello: {0} {1}'''.format(client_info, headers)

    @app.route('/print_elite')
    @auth.login_required
    #@apiprivs.priv_check('full-control')
    @priv_check('full-control')
    def print_auth2():
        #auth_user = request.authorization.username
        headers = request.headers
        enviro = request.environ
        autho_type = headers['Authorization']
        client_info = apiprivs._get_client_info()
        return '''Hello: {0} {1}'''.format(client_info, headers)


    @app.route('/')
    #@apiprivs.priv_check('full-control')
    @priv_check('identity')
    def index():
        if 'username' in session:
            return 'Logged in as %s' % escape(session['username'])
        return 'You are not logged in'
    
    
    @app.route('/hello/')
    @app.route('/hello/<name>')
    def hello(name=None):
        return render_template('hello.html', name=name)
    
    @app.route("/user/<username>")
    def show_user_profile(username):
        return 'User %s' % username
    
    @app.route('/post/<int:post_id>/')
    def show_post(post_id):
        return 'Post %d' % post_id
    
    @app.route('/inherit/')
    def inherit_template():
        return render_template('child_1.html')
    
    
    @app.route('/login', methods=['POST', 'GET'])
    def login():
        error = None
        if request.method == 'POST':
            if valid_login(request.form['username'],
                           request.form['password']):
                session['username'] = request.form['username']
                return redirect(url_for('index'))
            else:
                error = 'Invalid username/password'
        # the code below is executed if the request method
        # was GET or the credentials were invalid
        return render_template('login.html', error=error)
    
    def valid_login(username,password):
        if username == 'Dave' and password == 'lemon':
            return True
    
    
    @app.route('/logout')
    def logout():
        # remove the username from the session if it's there
        session.pop('username', None)
        return redirect(url_for('index'))
    
    
    
    def allowed_file(filename):
        return '.' in filename and \
               filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
    
    @app.route('/upload/', methods=['GET', 'POST'])
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
    
    
    @app.route('/uploaded/')
    def file_uploaded():
        return 'File uploaded'
    
    @app.route('/uploads/<filename>')
    def uploaded_file(filename):
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    
    @app.route('/scheduler')
    def print_scheduler():
        return schd


    with app.test_request_context():
        print url_for('index')
        print url_for('hello', name='Andre the Giant')
        print url_for('show_user_profile', username='Bob Marley')
        print url_for('show_post', post_id=1224 )



