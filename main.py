"""
Main file featuring all the functions to access the various pages.
"""

import datetime
import secrets

import flask
from flask import request
from flask import session
from flask_wtf.csrf import CSRFProtect

import login_security_handler
import sql_get_user_info


secret_key = secrets.token_hex(16)
# indicates where all files are for the app
app = flask.Flask(__name__, template_folder='templates', static_folder='staticFiles')
app.secret_key = secret_key

csrf.init_app(app)


@app.before_request
def abort_hostile_access():
    """
    In the event that a user fails to log in more than 10 times, their ip is banned
    from the site.
    :return:
    """
    user_ip = request.environ.get('REMOTE_ADDR')
    try:
        login_security_handler.check_ip(user_ip)
    except ValueError:
        flask.abort(403)


@app.route("/")
def home_page():
    """
    Renders the home page, starting site.
    Month and time are accessed by the site via datetime.
    :return:
    """
    if 'username' in session:
        session.pop('username', None)
    sql_get_user_info.generate_table()
    current_date = datetime.datetime.now()
    current_time = datetime.datetime.now().strftime('%I:%M %p')
    return flask.render_template('index.html', date=current_date, time=current_time)


@app.route("/about")
def about_page():
    """
    Renders the about page.
    :return:
    """
    if 'username' in session:
        session.pop('username', None)
    return flask.render_template('about.html')


@app.route("/login", methods=['GET', 'POST'])
def login_page():
    """
    Renders the login page.
    Uses security tools to validate the safety of the IP.
    If there is a suspected brute force, account is locked.
    Failed logins uptick the brute force check.
    On successful login attempts are reset.
    :return:
    """
    if 'username' in session:
        return flask.redirect(flask.url_for('account_home'), code=302)
    if request.method == 'POST':
        try:
            login_security_handler.check_ip(request.remote_addr)

            username = request.form['username']
            password = request.form['password']

            sql_get_user_info.verify_user(username, password)

        except ValueError as exception_reason:
            login_security_handler.log_failed_attempt(request.remote_addr)
            return flask.render_template('login.html', message=exception_reason)

        session['username'] = username
        login_security_handler.reset_ip_attempts(request.remote_addr)
        return flask.redirect(flask.url_for('account_home'), code=302)

    return flask.render_template('login.html')


@app.route("/register", methods=['GET', 'POST'])
def register_page():
    """
    Renders the registrations page. If the user has clicked submit,
    makes account. Data is stored in a sql table.
    :return:
    No return
    """
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        try:
            sql_get_user_info.new_user(username, password)
        except ValueError as exception_reason:
            return flask.render_template('registration.html', message=exception_reason)

        login_security_handler.reset_ip_attempts(request.remote_addr)
        return flask.redirect(flask.url_for('success_page'), code=302)

    return flask.render_template('registration.html')


@app.route("/account-success", methods=['GET', 'POST'])
def success_page():
    """
    Page notifies the user of successful account creation and redirects them
    to the login page.
    :return:
    """
    if request.method == 'POST':
        return flask.redirect(flask.url_for('login_page'), code=302)

    return flask.render_template('accountsuccess.html')


@app.route("/account-home", methods=['GET', 'POST'])
def account_home():
    """
    Page allows user to select their payment plan to unlock account features.
    Redirects to enter_payment.
    :return:
    """
    if request.method == 'POST':
        session.pop('username', None)
        return flask.redirect(flask.url_for('enter_payment'), code=302)

    return flask.render_template('accounthome.html')


@app.route("/payment-info", methods=['GET', 'POST'])
def enter_payment():
    """
    Brings the user to the enter payment page. After successfully entering their
    info, redirects to the secret page.
    :return:
    """
    if request.method == 'POST':
        return flask.redirect(flask.url_for('secret_page'), code=302)
    return flask.render_template('enterpayment.html')


@app.route("/secret-page")
def secret_page():
    """
    Currently just a picture. Still contains navbar so user can return to home,
    about, or login.
    :return:
    """
    return flask.render_template('underconstruction.html')


@app.route("/update-password", methods=['GET', 'POST'])
def update_password_page():
    """
    Allows user to update their password. If passes the update password method,
    the user is redirected to the login page.
    :return:
    """
    if request.method == 'POST':
        username = session['username']
        password = request.form['password']

        try:
            sql_get_user_info.update_password(username, password)
        except ValueError as exception_reason:
            return flask.render_template('updatepassword.html', message=exception_reason)
        return flask.redirect(flask.url_for('login_page'), code=302)
    return flask.render_template('updatepassword.html')


if __name__ == '__main__':
    app.run(debug=True)
