from flask import Flask, redirect, url_for, session
from flask import render_template
from flask_oauth import OAuth

from urllib2 import Request, urlopen, URLError

import json
from random import randint

# from pymongo import MongoClient

###################################

# MongoDB Section

###################################

# client = MongoClient()
#
# spliiit_db = client['spliiit']
#
# user_info = spliiit_db['user_info']
# event_info = spliiit_db['event_info']
#
# def addNewUser(user_details):
# 	user_obj = dict()
# 	user_obj['uid'] = user_details['uid']
# 	user_obj['name'] = user_details['name']
# 	user_obj['email'] = user_details['email']
# 	user_obj['picture'] = user_details['picture']
# 	user_obj['friends'] = list()
# 	user_obj['events'] = list()
#
# 	user_info.insert_one(user_obj)
#
# def checkUserExists(uid):
# 	if user_info.find_one({'uid': uid}) == None:
# 		return False
# 	return True

###################################





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

# Endpoints Section

###################################

@app.route('/')
def home():
	status = handle_auth()
	if status['access_granted'] == False:
		return render_login_page()

	user_data = get_user_data(status['data'])

	# if not checkUserExists(user_data['uid']):
	# 	addNewUser(user_data)
	# 	print "Added New User!"
	# 	# return addNewUserWorkflow

	return render_template('home.html',
			t=randint(1,9999),
			user_data=user_data)

@app.route('/admin')
def admin():
	status = handle_auth()
	if status['access_granted'] == False:
		return status['action_taken']

	user_data = get_user_data(status['data'])

	return render_template('admin.html',
			t=randint(1,9999),
			user_data=user_data)

@app.route('/dummy')
def dummy():
	status = handle_auth()
	if status['access_granted'] == False:
		return status['action_taken']

	user_data = get_user_data(status['data'])

	return render_template('dummy_land2.html',
			t=randint(1,9999),
			user_data=user_data)

###################################





###################################

# Application Configuration Section

###################################

def main():
    app.run()

if __name__ == '__main__':
    main()

###################################
