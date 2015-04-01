# -*- coding: utf-8 -*-
import os, urllib, hashlib, string, sendgrid, re, base64
from sendgrid import SendGridError, SendGridClientError, SendGridServerError
from datetime import datetime
from flask import Flask, request, flash, url_for, redirect, \
     render_template, abort, send_from_directory, session, abort, g, jsonify
from flask_sqlalchemy import SQLAlchemy
from  sqlalchemy.sql.expression import func, select
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import Form, BooleanField, TextField, PasswordField, TextAreaField, SelectField, FileField, HiddenField, DateField, IntegerField, DateTimeField, validators, ValidationError
from wtforms.ext.sqlalchemy.orm import QuerySelectField, QuerySelectMultipleField
from slugify import slugify
from flask.ext.login import LoginManager, current_user, current_app, login_required, login_user, logout_user, confirm_login, fresh_login_required
from flask_oauth import OAuth, OAuthException
from functools import wraps
from flask.ext.sqlalchemy import SQLAlchemy
from sqlalchemy.orm import object_session
from sqlalchemy import or_, not_
from  sqlalchemy.sql.expression import func
from flask.ext.heroku import Heroku
from uuid import uuid4
from urlparse import urlparse, urljoin
from random import *

app = Flask(__name__)

# Conf
app.config.from_pyfile('config.cfg')
# Prod
if 'DATABASE_URL' in os.environ:
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['DATABASE_URL']
# Dev
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://localhost/slottet'

# Init events
heroku = Heroku(app)
db = SQLAlchemy(app)
# Init login manager
login_manager = LoginManager()
login_manager.init_app(app)
# oauth for Facebook
oauth = OAuth()
facebook = oauth.remote_app('facebook',
    base_url='https://graph.facebook.com/',
    request_token_url=None,
    access_token_url='/oauth/access_token',
    authorize_url='https://www.facebook.com/dialog/oauth',
    consumer_key=app.config['FACEBOOK_APP_ID'],
    consumer_secret=app.config['FACEBOOK_APP_SECRET'],
    request_token_params={'scope': 'email'}
)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@login_manager.unauthorized_handler
def unauthorized_callback():
    return redirect('/login?next=' + request.path)

# Attach current user to global object
@app.before_request
def before_request():
    g.user = current_user

class Role(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))

    def __init__(self, name, description):
        self.name = name
        self.description = description

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True, index=True)
    facebook_user_id = db.Column(db.String)
    email = db.Column(db.String(255), unique=True, index=True)
    pwd_hash = db.Column(db.String(255))
    first_name = db.Column(db.String)
    last_name = db.Column(db.String)
    permalink = db.Column(db.String, unique=True)
    company_name = db.Column(db.String)
    description = db.Column(db.Text)
    community_contribute = db.Column(db.String)
    community_need = db.Column(db.String)
    website = db.Column(db.Text)
    gender = db.Column(db.String)
    twitter_handle = db.Column(db.String)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'))
    role = db.relationship("Role")
    registered_at = db.Column(db.DateTime)

    def __init__(self, email, password, first_name, last_name, facebook_user_id):
        self.email = email
        self.set_password(password)
        self.first_name = first_name
        self.last_name = last_name
        self.facebook_user_id = facebook_user_id
        self.permalink = slugify(first_name + last_name)
        self.registered_at = datetime.utcnow()

    # Flask-Login integration
    def is_authenticated(self):
        return True

    def is_active(self):
        return self.is_active

    def is_anonymous(self):
        return False

    def get_id(self):
        return self.id

    def get_email(self):
        return self.email

    def get_role(self):
        return self.role.name

    def is_admin(self):
        return True if self.role.name == "ADMIN" else False

    def set_password(self, password):
        self.pwd_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.pwd_hash, password)

    # Required for administrative interface 
    def __unicode__(self):
        return self.first_name + " " + self.last_name

# Login required decorator. Supports Facebook Login. v0.2
def login_required(role="ANY"):
    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            if not current_user.is_authenticated():
                return current_app.login_manager.unauthorized()
            urole = current_user.get_role()
            if ( (urole != role) and (role != "ANY")):
                flash(u'Du har inte behörighet att göra detta.', 'primary')
                return redirect(url_for("index"))
            return fn(*args, **kwargs)
        return decorated_view
    return wrapper

def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
           ref_url.netloc == test_url.netloc

def get_redirect_target():
    for target in request.args.get('next'), request.referrer:
        if not target:
            continue
        if is_safe_url(target):
            return target

class UserForm(Form):
    community_contribute = TextField(u'Vad kan du bidra med?', [validators.required(message=u'Detta fält måste fyllas i.'), validators.Length(max=1000)], description=u"T ex programmeringskunskap eller en kram")
    community_need = TextField(u'Vad behöver du just nu?', [validators.required(message=u'Detta fält måste fyllas i.'), validators.Length(max=1000)], description=u"T ex feedback på marknadsplan eller färsk ekologisk mango")
    email = TextField(u'E-postadress där vi kan nå dig', [validators.required(message=u'Detta fält måste fyllas i.'), validators.Length(max=255)], description=u"namn@domän.se")
    company_name = TextField(u'Namn på ditt företag eller projekt', [validators.required(message=u'Detta fält måste fyllas i.')], description=u"T ex Slottet AB eller Hittepåföretag")
    website = TextField(u'Hemsida där vi kan läsa mer', [validators.required(message=u'Detta fält måste fyllas i.')], description=u"")

@app.route('/', methods=['GET', 'POST'])
@app.route('/<path:permalink>', methods=['GET', 'POST'])
def index(permalink = ""):
    if permalink:
        user = User.query.filter_by(permalink=permalink).first()
        if not user:
            abort(404)
        return render_template('profile.html', user=user) 
    else:
        users = User.query.all()
        return render_template('index.html', users=users)


@app.route('/edit',methods=['GET','POST'])
@login_required()
def edit():
    form = UserForm(request.form, current_user)
    if request.method == 'POST' and form.validate():
        current_user.community_contribute = form.community_contribute.data
        current_user.community_need = form.community_need.data
        current_user.email = form.email.data
        current_user.company_name = form.company_name.data
        current_user.website = form.website.data
        db.session.commit()
        flash(u'Tack %s! Din profil har uppdaterats' % current_user.first_name, 'primary')
        return redirect(url_for('index'))
    return render_template('form.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    return facebook.authorize(callback=url_for('facebook_authorized',
        next=request.args.get('next') or request.referrer or None,
        _external=True))

# Purpose: Handle login for Facebook. v0.1
@app.route('/login/authorized', methods=['GET', 'POST'])
@facebook.authorized_handler
def facebook_authorized(resp):
    next = get_redirect_target() or ''
    if resp is None:
        flash(u'Åtkomst nekas: anledning=%s felbeskrivning=%s' % (request.args['error_reason'],request.args['error_description']), 'primary')
        redirect(url_for('index'))
    if isinstance(resp, OAuthException):
        flash(u'Åtkomst nekas: %s' % (resp.message), 'primary')
        redirect(url_for('index'))
    session['oauth_token'] = (resp['access_token'], '')
    me = facebook.get('/me')
    if 'id' and 'email' in me.data:
        user = User.query.filter(or_(User.facebook_user_id == me.data['id'], User.email == me.data['email'])).first()
    else:
        flash(u'Slottet behöver åtkomst till din e-postadress för att skapa ditt konto.', 'primary')
        redirect(url_for('index'))
    # Create user
    if not user:
        user = User(me.data['email'], generate_secure_password(), me.data['first_name'], me.data['last_name'], me.data['id'])
        if 'gender' in me.data:
            user.gender = me.data['gender']
        user_role = Role.query.filter_by(name="USER").first()
        user.role = user_role
        db.session.add(user)   
    db.session.commit()
    login_user(user)
    # return redirect(request.args.get('next') or url_for('edit'))
    return redirect(url_for('edit'))

@facebook.tokengetter
def get_facebook_oauth_token():
    return session.get('oauth_token')

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("index"))

# Send email using Sendgrid. v0.1
def send_email(to_email,subject,msg_html,from_email="",bcc_email=""):
    message = sendgrid.Mail()
    message.add_to(to_email)
    message.set_subject(subject)
    message.set_html(msg_html)
    message.set_from(from_email) if from_email else message.set_from(app.config['SENDGRID_DEFAULT_MAIL_SENDER'])
    message.add_bcc(bcc_email) if bcc_email else None
    status, msg = sg.send(message)
    return status

def generate_secure_password():
    # Generate secure password
    characters = string.ascii_letters + string.digits + string.punctuation
    password = "".join(choice(characters) for x in range(randint(8, 16)))
    return password

if __name__ == '__main__':
    app.run()
