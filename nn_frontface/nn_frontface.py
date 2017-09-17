from flask import Flask, redirect, url_for, session
from flask import render_template, abort
from flask_oauth import OAuth

from urllib2 import Request, urlopen, URLError

import json
from random import randint


###################################

# Google Auth Section

###################################

GOOGLE_CLIENT_ID = '7200729897-m5bft547a6ln5kg5sr9dvte7ie8irpco.apps.googleusercontent.com'
GOOGLE_CLIENT_SECRET = 'acdxjQY0eKibY2lnIWRcAoQd'
REDIRECT_URI = '/oauth2callback'  # one of the Redirect URIs from Google APIs console

SECRET_KEY = 'maya4lyf'
DEBUG = True

app = Flask(__name__)
app.debug = DEBUG
app.secret_key = SECRET_KEY
oauth = OAuth()

google = oauth.remote_app('google',
							base_url='https://www.google.com/accounts/',
							authorize_url='https://accounts.google.com/o/oauth2/auth',
							request_token_url=None,
							request_token_params={'scope': 'https://www.googleapis.com/auth/userinfo.email',	'response_type': 'code'},
							access_token_url='https://accounts.google.com/o/oauth2/token',
							access_token_method='POST',
							access_token_params={'grant_type': 'authorization_code'},
							consumer_key=GOOGLE_CLIENT_ID,
							consumer_secret=GOOGLE_CLIENT_SECRET)

@app.route(REDIRECT_URI)
@google.authorized_handler
def authorized(resp):
    access_token = resp['access_token']
    session['access_token'] = access_token, ''
    return redirect(url_for('home'))

@google.tokengetter
def get_access_token():
    return session.get('access_token')

@app.route('/login_google')
def login_google():
    callback=url_for('authorized', _external=True)
    return google.authorize(callback=callback)

@app.route('/logout')
def logout():
	session.pop('access_token', None)
	return redirect(url_for('home'))

def handle_auth():
	access_token = session.get('access_token')

	result = dict()
	result['access_granted'] = False

	if access_token is None:
		result['action_taken'] = redirect(url_for('home'))
		return result

	access_token = access_token[0]

	headers = {'Authorization': 'OAuth '+access_token}
	req = Request('https://www.googleapis.com/oauth2/v1/userinfo',
					None, headers)
	try:
		res = urlopen(req)
	except URLError, e:
		if e.code == 401:
			# Unauthorized - bad token
			session.pop('access_token', None)
			result['action_taken'] = redirect(url_for('home'))
			return result

	result['access_granted'] = True
	result['data'] = json.loads(res.read())

	# print result['data']

	return result

###################################





###################################

# Helper Functions Section

###################################

def render_login_page():
	return render_template('login.html',
		t=randint(1,9999))

def get_user_data(datastore):
	details = dict()

	# print datastore
	details['uid'] = datastore['id']
	details['name'] = datastore['name']
	details['email'] = datastore['email']
	details['picture'] = datastore['picture']

	return details

###################################

###################################

# Endpoints for Patient Section

###################################

@app.route('/history')
def history():
	status = handle_auth()
	if status['access_granted'] == False:
		return status['action_taken']

	user_data = get_user_data(status['data'])

	labels = ["Aug 30", "Aug 31", "Sep 1", "Sep 2", "Sep 3", "Sep 4", "Sep 5"]

	TTB = [-2, -1.2, -3, -4.3, -2.3, -3.9, -1]
	SST = [-1, -0.2, -2, -4, -1.3, -3, -0.5]
	FW = [8, 7, 5, 5.8, 6, 9, 10]
	TOB = [9, 8, 5.4, 6.3, 6.7, 9.5, 10]


	return render_template('history.html',
			t=randint(1,9999),
			user_data=user_data,
			labels=labels,
			TTB=repr(TTB),
			SST=repr(SST),
			FW=repr(FW),
			TOB=repr(TOB))

@app.route('/profile')
def profile():
	status = handle_auth()
	if status['access_granted'] == False:
		return status['action_taken']

	user_data = get_user_data(status['data'])

	return render_template('profile.html',
			t=randint(1,9999),
			user_data=user_data)

@app.route('/profile/preferences')
def profile_preferences():
	status = handle_auth()
	if status['access_granted'] == False:
		return status['action_taken']

	user_data = get_user_data(status['data'])

	return render_template('profile_preferences.html',
			t=randint(1,9999),
			user_data=user_data)

@app.route('/profile/devices')
def profile_devices():
	status = handle_auth()
	if status['access_granted'] == False:
		return status['action_taken']

	user_data = get_user_data(status['data'])

	return render_template('profile_devices.html',
			t=randint(1,9999),
			user_data=user_data)

@app.route('/profile/assistance')
def profile_assistance():
	status = handle_auth()
	if status['access_granted'] == False:
		return status['action_taken']

	user_data = get_user_data(status['data'])

	return render_template('profile_assistance.html',
			t=randint(1,9999),
			user_data=user_data)

@app.route('/support')
def support():
	status = handle_auth()
	if status['access_granted'] == False:
		return status['action_taken']

	user_data = get_user_data(status['data'])

	return render_template('support.html',
			t=randint(1,9999),
			user_data=user_data)

@app.route('/support/FAQ')
def support_FAQ():
	status = handle_auth()
	if status['access_granted'] == False:
		return status['action_taken']

	user_data = get_user_data(status['data'])

	return render_template('support_FAQ.html',
			t=randint(1,9999),
			user_data=user_data)

@app.route('/support/chat')
def support_chat():
	status = handle_auth()
	if status['access_granted'] == False:
		return status['action_taken']

	user_data = get_user_data(status['data'])

	return render_template('support_chat.html',
			t=randint(1,9999),
			user_data=user_data)

@app.route('/support/helplines')
def support_helplines():
	status = handle_auth()
	if status['access_granted'] == False:
		return status['action_taken']

	user_data = get_user_data(status['data'])

	return render_template('support_helplines.html',
			t=randint(1,9999),
			user_data=user_data)

@app.route('/about')
def about():
	status = handle_auth()
	if status['access_granted'] == False:
		return status['action_taken']

	user_data = get_user_data(status['data'])

	return render_template('about.html',
			t=randint(1,9999),
			user_data=user_data)

@app.route('/about/contactus')
def about_contactus():
	status = handle_auth()
	if status['access_granted'] == False:
		return status['action_taken']

	user_data = get_user_data(status['data'])

	return render_template('about_contactus.html',
			t=randint(1,9999),
			user_data=user_data)

@app.route('/troubleshoot')
def troubleshoot():
	status = handle_auth()
	if status['access_granted'] == False:
		return status['action_taken']

	user_data = get_user_data(status['data'])

	return render_template('troubleshoot.html',
			t=randint(1,9999),
			user_data=user_data)

###################################

###################################

# Endpoints for Admin Section and rerouting

###################################

@app.route('/')
def home():
	status = handle_auth()
	if status['access_granted'] == False:
		return render_login_page()

	user_data = get_user_data(status['data'])

	return render_template('home.html',
			t=randint(1,9999),
			user_data=user_data,
			bedtime="10:00 PM",
			waketime="07:00 AM")

@app.route('/b')
def home_t():
	status = handle_auth()
	if status['access_granted'] == False:
		return render_login_page()

	userType = "patient"
	user_data = get_user_data(status['data'])

	return render_template('home.html',
			t=randint(1,9999),
			user_data=user_data,
			bedtime="10:00 PM",
			waketime="07:00 AM")

@app.route('/admin')
def admin():
	status = handle_auth()
	if status['access_granted'] == False:
		return status['action_taken']

	isAdmin = True

	if not isAdmin:
		return "404"

	user_data = get_user_data(status['data'])

	return render_template('admin.html',
			t=randint(1,9999),
			user_data=user_data)

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

###################################

###################################

# Application Configuration Section

###################################

def main():
    app.run(port=5001)

if __name__ == '__main__':
    main()

###################################
