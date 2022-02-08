from flask import render_template, request, session, redirect, url_for
from functools import wraps
from c499 import app
import c499.backend as bn
import re
import datetime
import sys

"""
This file defines the front-end part of the service.
It elaborates how the services should handle different
http requests from the client (browser) through templating.
The html templates are stored in the 'templates' folder.
"""


@app.route('/register', methods=['GET'])
def register_get():

    # if the user is logged in already, redirect to home page
    if 'logged_in' in session:
        return redirect('/', code=303)

    # templates are stored in the templates folder
    return render_template('register.html', message='Please register')


@app.route('/register', methods=['POST'])
def register_post():
    email = request.form.get('email')
    name = request.form.get('name')
    password = request.form.get('password')
    password2 = request.form.get('password2')

    # regex's to check the inputs against
    # please note that the email pattern doesn't actually work for all RFC5322 emails
    # if you can find a regex that does please replace it and then remove this comment, thanks
    #passwordPattern = re.compile("(?=.*[a-z])(?=.*[A-Z])(?=.*([!-/]|[:-@])).{6,}")
    passwordPattern = re.compile("^.{6,99}$")
    emailPattern = re.compile("([!#-'*+/-9=?A-Z^-~-]+(\.[!#-'*+/-9=?A-Z^-~-]+)*|\"([]!#-[^-~ \t]|(\\[\t -~]))+\")@([0-9A-Za-z]([0-9A-Za-z-]{0,61}[0-9A-Za-z])?(\.[0-9A-Za-z]([0-9A-Za-z-]{0,61}[0-9A-Za-z])?)*|\[((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}|IPv6:((((0|[1-9A-Fa-f][0-9A-Fa-f]{0,3}):){6}|::((0|[1-9A-Fa-f][0-9A-Fa-f]{0,3}):){5}|[0-9A-Fa-f]{0,4}::((0|[1-9A-Fa-f][0-9A-Fa-f]{0,3}):){4}|(((0|[1-9A-Fa-f][0-9A-Fa-f]{0,3}):)?(0|[1-9A-Fa-f][0-9A-Fa-f]{0,3}))?::((0|[1-9A-Fa-f][0-9A-Fa-f]{0,3}):){3}|(((0|[1-9A-Fa-f][0-9A-Fa-f]{0,3}):){0,2}(0|[1-9A-Fa-f][0-9A-Fa-f]{0,3}))?::((0|[1-9A-Fa-f][0-9A-Fa-f]{0,3}):){2}|(((0|[1-9A-Fa-f][0-9A-Fa-f]{0,3}):){0,3}(0|[1-9A-Fa-f][0-9A-Fa-f]{0,3}))?::(0|[1-9A-Fa-f][0-9A-Fa-f]{0,3}):|(((0|[1-9A-Fa-f][0-9A-Fa-f]{0,3}):){0,4}(0|[1-9A-Fa-f][0-9A-Fa-f]{0,3}))?::)((0|[1-9A-Fa-f][0-9A-Fa-f]{0,3}):(0|[1-9A-Fa-f][0-9A-Fa-f]{0,3})|(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3})|(((0|[1-9A-Fa-f][0-9A-Fa-f]{0,3}):){0,5}(0|[1-9A-Fa-f][0-9A-Fa-f]{0,3}))?::(0|[1-9A-Fa-f][0-9A-Fa-f]{0,3})|(((0|[1-9A-Fa-f][0-9A-Fa-f]{0,3}):){0,6}(0|[1-9A-Fa-f][0-9A-Fa-f]{0,3}))?::)|(?!IPv6:)[0-9A-Za-z-]*[0-9A-Za-z]:[!-Z^-~]+)])")
    lengthPattern = re.compile("^.{1,63}$")
    usernamePattern = re.compile("^[\w][\w| ]{0,18}[\w]$")

    # check for errors
    error = False

    # check that both passwords match
    if password != password2:
        message="passwords do not match"
        error = True

    # check that the forms all match the required patterns using regular expressions
    elif not(emailPattern.match(email)) or not(lengthPattern.match(email)):
        message="invalid email"
        error = True
    elif not(passwordPattern.match(password)):
        message="password must be at least 6 characters long"
        error = True
    elif not(usernamePattern.match(name)):
        message="username must be alphanumeric, no more than 18 characters long"
        error = True

    # if all forms are correct, attempt to register the user
    if not(error):
        user = bn.get_user(email)
        # if the user already exists, send an error message
        if user:
            return render_template('register.html', message="this email has been ALREADY used")
        # if the registration fails for some reason (register_user doesn't return none) send an error message
        elif bn.register_user(email, name, password, password2) != None:
            return render_template('register.html', message="failed to register new user, please try again")
        # if no errors occur, set balance to 5000
        else:
            message = "Registration successful, please login now"
        
        return redirect(url_for('login_get', message=message))

    # otherwise, display the error message
    else:
        return render_template('register.html', message=message)



@app.route('/login', methods=['GET'])
def login_get():

    # if the user is logged in already, redirect to home page
    if 'logged_in' in session:
        return redirect('/', code=303)

    # if a message was passed to this function, display that as message. else, display 'Please login'
    passed_message = request.args.get('message')
    if passed_message == None:
        passed_message = 'Sign in to continue'
    return render_template('login.html', message=passed_message)


@app.route('/login', methods=['POST'])
def login_post():

    # get the user's form inputs
    email = request.form.get('email')
    password = request.form.get('password')
    # attempt to login with those user credentials
    user = bn.login_user(email, password)

    # if bn.login_user succeeds, add that user's email to the session (as 'logged_in')
    # then redirect them to the homepage
    if user:
        session['logged_in'] = user.email
        """
        Session is an object that contains sharing information
        between browser and the end server. Typically it is encrypted
        and stored in the browser cookies. They will be past
        along between every request the browser made to this services.

        Here we store the user object into the session, so we can tell
        if the client has already login in the following sessions.

        """
        # success! go back to the home page
        # code 303 is to force a 'GET' request
        return redirect('/', code=303)

    # if login failed, check what the error was and display an appropriate error message
    else:
        return render_template('login.html', message='Incorrect Email or Password')


@app.route('/logout', methods=['GET'])
def logout():
    # check if there is a user currently logged_in in this session
    # if there is, set 'logged_in' to None to log them out
    if 'logged_in' in session:
        session.pop('logged_in', None)

    # always redirect to homepage
    # since the user is logged out at this point, this should immediately redirect to /login
    return redirect('/', code=303)

@app.route('/forgot')
def forgot():
    return render_template('forgot.html')

def authenticate(inner_function):
    """
    :param inner_function: any python function that accepts a user object

    Wrap any python function and check the current session to see if
    the user has logged in. If login, it will call the inner_function
    with the logged in user object.

    To wrap a function, we can put a decoration on that function.
    Example:

    @authenticate
    def home_page(user):
        pass
    """
    @wraps(inner_function)
    def wrapped_inner():

        # check did we store the key in the session
        if 'logged_in' in session:
            email = session['logged_in']
            user = bn.get_user(email)
            if user:
                # if the user exists, call the inner_function
                # with user as parameter
                return inner_function(user)
        else:
            # else, redirect to the login page
            return redirect('/login', code=303)

    # return the wrapped version of the inner_function:
    return wrapped_inner

@app.route('/')
@authenticate
def home(user):
    # authentication is done in the wrapper function
    # see above.
    # by using @authenticate, we don't need to re-write
    # the login checking code all the time for other
    # front-end portals
    welcome_header='Welcome, {}'.format(user.name)
    return render_template('index.html', welcome_header=welcome_header, user=user)

@app.route('/profile')
@authenticate
def profile(user):
    return render_template('profile.html', user=user)

@app.route('/report')
@authenticate
def report(user):
    return render_template('report.html', user=user)

@app.route('/map')
@authenticate
def map(user):
    return render_template('map.html', user=user)

@app.route('/about')
@authenticate
def about(user):
    return render_template('about.html', user=user)

@app.route('/history')
@authenticate
def history(user):
    return render_template('history.html', user=user)

@app.route('/settings')
@authenticate
def settings(user):
    return render_template('settings.html', user=user)

@app.errorhandler(404)
def other_requests(error):
    # returns a 404 error for any other requests
    return render_template('404.html', message='404 ERROR: The requested URL was not found on the server.'), 404
