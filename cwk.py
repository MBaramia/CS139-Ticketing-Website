from flask_sqlalchemy import SQLAlchemy
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_login import login_required, login_user, logout_user, current_user, LoginManager, UserMixin
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime
import barcode
from barcode.writer import ImageWriter
import random
import string
from io import BytesIO
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
import secrets

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///User.sqlite' 
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'secret_key'
app.config['SECURITY_PASSWORD_SALT'] = 'password salt'
app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'mo.dulla20@gmail.com'
app.config['MAIL_PASSWORD'] = 'pnkivogrhzlfjexx'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True

mail = Mail(app)

s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)


class User(db.Model, UserMixin): #store User information into database table
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(50), nullable=False)
    access_user = db.Column(db.String(30), unique=True, nullable=False)
    is_verifieduser = db.Column(db.Boolean, default=False, nullable=False)

    def __init__(self, name, email, password):
        self.name=name
        self.email = email
        self.password = password

class Events(db.Model): #store Events information into database table
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    date = db.Column(db.String(50), nullable=False)
    cost = db.Column(db.Float, nullable = False)
    place = db.Column(db.String(30), nullable= False)
    capacity = db.Column(db.Integer, nullable=False)
    organiser_id = db.Column(db.Integer, db.ForeignKey('organiser.id'), nullable=False)



    def __init__(self, name, date, cost, place, capacity, organiser_id):
        self.name = name
        self.date=date
        self.cost=cost
        self.place=place
        self.capacity=capacity
        self.organiser_id=organiser_id


class Ticket(db.Model): #store Ticket information in the database
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey('events.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    barcode = db.Column(db.String(50), unique=True, nullable=False)

    def __init__(self, event_id, user_id, quantity):
        self.event_id=event_id
        self.user_id=user_id
        self.quantity=quantity
        self.barcode=barcode


class Organiser(db.Model, UserMixin): #store Organiser information into database table
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), unique = True, nullable=False)
    email = db.Column(db.String(100), unique = True, nullable=False)
    password = db.Column(db.String(50), unique=False, nullable=False)
    access_token = db.Column(db.String(30), unique=True, nullable=False)
    is_verifiedorganiser = db.Column(db.Boolean, default=False, nullable=False)

    def __init__(self, name, email, password):
        self.name=name
        self.email=email
        self.password=password
        
resetdb = False
if resetdb:
    with app.app_context():
        db.drop_all()
        db.create_all()


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login(): #route to handle picking login type
    return render_template('login.html')

@app.route('/login/user', methods=['GET', 'POST'])
def login_user(): #route to handle user logging in
    if request.method == 'POST':
        print(123)
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session['access_user'] = user.access_user #allows user to access user only pages
            db.session.commit()
            return redirect(url_for('index'))
        else:
            error_message = 'Invalid email or password'
            return render_template('login_user.html', error_message=error_message)
    else:
        print(345)
        return render_template('login_user.html')

@app.route('/login/organiser', methods=['GET', 'POST'])
def login_organiser(): #route to handle organiser logging in
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        organiser = Organiser.query.filter_by(email=email).first()
        if organiser and check_password_hash(organiser.password, password):
            session['access_token'] = organiser.access_token #allows organiser to access organiser only pages
            db.session.commit()
            return redirect(url_for('index'))
        else:
            error_message='Invalid email or password'
            return render_template('login_organiser.html', error_message=error_message)
    else:
        return render_template('login_organiser.html')


@app.route('/register')
def register(): #route to handle picking registration type 
    return render_template('register.html')

@app.route('/register/user', methods=['GET', 'POST'])
def register_user(): #route for the user to register
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        hashed_password = generate_password_hash(password, method='sha256',salt_length=16)

        if password != confirm_password: #renders error_message on html file as you have used wrong passwords
            error_message = 'Your passwords do not match'
            return render_template('register_user.html', error_message=error_message)
        elif user_exists(email): #renders error_message on html file as account already exists
            error_message = 'User with this email address already exists'
            return render_template('register_user.html', error_message=error_message)

        else: #creates an attendee account and sends confirmation email with OTP
            create_user(name, email, hashed_password)
            passcode = generate_passcode()
            subject = "Confirm your email for WarwickTikits!"
            body = f"Your OTP is {passcode}. Enter this on the confirmation page to complete your registration now."
            send_email(recipient=email, subject=subject, body=body)

            return redirect(url_for('confirm_email', email=email, passcode=passcode))
    else:

        return render_template('register_user.html')

@app.route('/register/organiser', methods=['GET', 'POST'])
def register_organiser(): #route for the organiser to register
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        code = request.form['code']
        hashed_password = generate_password_hash(password, method='sha256',salt_length=16)

        if password != confirm_password: #renders error_message on html file as you have used wrong passwords
            error_message = 'Your passwords do not match'
            return render_template('register_organiser.html', error_message=error_message)
        elif organiser_exists(email): #renders error_message on html file as account already exists
            error_message = 'This account already exists'
            return render_template('register_organiser.html', error_message=error_message)
        elif code == 'Dc5_G1gz': #if the code is correct, create an organiser account and send confirmation email with OTP
            
                create_organiser(name, email, hashed_password)
                passcode = generate_passcode()
                subject = "Confirm your email for WarwickTikits!"
                body = f"Your one-time passcode is {passcode}. Enter this on the confirmation page to complete your registration."
                send_email(recipient=email, subject=subject, body=body)
        
                return redirect(url_for('confirm_email', email=email, passcode=passcode))
        else:
            error_message = 'You have provided the wrong code' #renders error_message as person gave wrong code
            return render_template('register_organiser.html', error_message=error_message)

    else:

        return render_template('register_organiser.html')

@app.route('/confirm_email/<passcode>')
def confirm_email(passcode): #route for confirming emails
    try:
        email = s.loads(token, salt='email-verification', max_age=3600)
        user = User.query.filter_by(email=email).first()
        organiser = Organiser.query.filter_by(email=email).first()
        if user: 
            user.is_verifieduser = True #verifies the user
            db.session.commit()
            return render_template('confirm_email.html')
        elif organiser:
            organiser.is_verifiedorganiser = True #verifies the organiser
            db.session.commit()
            return render_template('confirm_email.html')
        else:
            error_message = 'Invalid email address.'
            return render_template('confirm_email.html', error_message=error_message)
    except:
        return redirect(url_for('login'))

@app.route('/addEvent', methods=['GET', 'POST'])
def addEvent(): #route for only organiisers to add events

    if 'access_token' in session: #ensure only organisers can access this page

        if request.method == 'POST':
            name = request.form['name']
            date = request.form['date']
            cost = request.form['cost']
            place = request.form['place']
            capacity = request.form['capacity']
            organiser_id=session.get('organiser_id')
            event = Events(name=name, date=date, cost=cost, place=place, capacity=capacity, organiser_id=organiser_id) #add event to events table
            print(event.organiser_id)
            db.session.add(event) #add event to the database
            db.session.commit()
            session['event_id'] = event.id
            return redirect(url_for('index'))
        return render_template('addEvent.html')
    else:

        return redirect(url_for('login'))

@app.route('/logout')
def logout(): #route to log out
    session.pop('user_id',None)
    session.pop('organiser_id',None)
    session.clear() #clears the session
    logout_user()
    return redirect(url_for('index'))

@app.route('/lists')
def event_list(): #route for listing events
    events = Events.query.all()
    return render_template('lists.html', events=events)

@app.route('/purchase_ticket', methods=['GET','POST'])
def purchase_ticket(): #route for only users to buy tickets
    organiser = Organiser.query.first()
    email = organiser.email
    org = Organiser.query.filter_by(email=email).first()
    if 'access_user' in session: #ensures only attendees can access this page

        events = Events.query.all()
        if request.method == 'POST':
            event_id = request.form['event_id']
            quantity = int(request.form['quantity'])
            event = Events.query.get(event_id)
            if event is None: #attendee gave event id which doesnt exist
                error_message = 'There is no such event'
                return render_template('purchase_ticket.html', events=events, error_message=error_message)
            if event.capacity < quantity:
                error_message = 'Sorry, there are not enough tickets available'
                return render_template('purchase_ticket.html', events=events, error_message=error_message)
            if event.capacity == quantity: #sends email to organiser that event is max capacity
                subject = "Maximum Capacity!"
                body = f"This is an email being sent to you from WarwickTikits to confirm to you that your event {event} has reached maximum capacity"
                send_email(recipient=email, subject=subject, body=body)
            if (quantity/event.capacity <= 0.1): #sends email to organiser that event is near capacity
                subject = "Nearly Full!"
                body = f"This is an email being sent to you from WarwickTikits to confirm to you that your event {event} has nearly reached maximum capacity, and is 90% full."
                send_email(recipient=email, subject=subject, body=body)

            event.capacity -= quantity #reduces capacity of event
            for i in range(1,quantity+1):
                user_id = session['user_id']
                ticket = Ticket(event_id=event_id, user_id=user_id, quantity=quantity)
                ticket.barcode = secrets.token_hex(30) #creates barcode for ticket
                db.session.commit()
                db.session.add(ticket)
                db.session.commit()
            return redirect(url_for('dashboard'))
        else:
            return render_template('purchase_ticket.html', events=events)
    else:
        return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard(): #route for user dashboard
    if 'access_user' in session:
        user_id = session.get('user_id')
        ticket = Ticket.query.filter_by(user_id=user_id).all()
        return render_template('dashboard.html', ticket=ticket)
    else:
        return redirect(url_for('login'))

def create_user(name, email, hashed_password): #method to create a user
    user = User(name=name, email=email, password=hashed_password)
    user.access_user = secrets.token_hex(12) #creates access_user token
    user.is_verifieduser = True
    db.session.commit()
    session['access_user'] = user.access_user
    db.session.add(user)
    db.session.commit()
    session['user_id'] = user.id

def validate_user(email, password): #method to make sure user password is right.
    user = User.query.filter_by(email=email).first()
    if user and user.password == password:
        return True
    else:
        return False

def validate_organiser(email, password): #method to make sure organiser password
    organiser = Organiser.query.filter_by(email=email).first()
    if organiser and organiser.password == password:
        return True
    else:
        return False

def user_exists(email): #method for if the user email already being used
    user = User.query.filter_by(email=email).first()
    if user:
        return True
    else:
        return False

def organiser_exists(email): #method to check if organiser exists
    organiser = Organiser.query.filter_by(email=email).first()
    if organiser:
        return True
    else:
        return False

def create_organiser(name, email, hashed_password): #method to create an organiser
    organiser = Organiser(name=name, email=email, password=hashed_password)
    organiser.access_token = secrets.token_hex(12) #creates access_token for organiser
    organiser.is_verifiedorganiser = True
    db.session.commit()
    session['access_token'] = organiser.access_token
    db.session.add(organiser)
    db.session.commit()
    session['organiser_id'] = organiser.id

@app.route('/cancel_event', methods=['GET', 'POST'])
def cancel_event(): #method for only organisers to cancel events
    if 'access_token' in session: #ensures only organisers can acess this page, else they get sent to login
        if request.method == 'POST':
            event_id = request.form['event_id']
            event = Events.query.get(event_id)
            if event: #if the event exists
                    db.session.delete(event)
                    db.session.commit()
                    tickets = Ticket.query.filter_by(event_id=event_id).all()
                    db.session.commit()
                    for ticket in tickets: #method which sends emails to attendees that the event is cancelled.
                        user = User.query.filter_by(id=ticket.user_id).first()
                        email = user.email
                        if user:
                            subject = "Event cancellation!"
                            body = f"It is with deep sorrow that we must tell you that the event {event} has been cancelled. We are sorry for any inconveniences."
                            send_email(recipient=email, subject=subject, body=body)
                    db.session.delete(ticket)
                    db.session.commit()
            else:
                error_message='Event was not found' #no such event to be cancelled
                return render_template('cancel_event.html', error_message=error_message)
        return render_template('cancel_event.html')
    else:
        return redirect(url_for('login'))

@app.route('/cancel_ticket', methods=['GET','POST'])
def cancel_ticket(): #route for only users to cancel tickets
    if 'access_user' in session:
        if request.method == 'POST':
            ticket_id = request.form['ticket_id'] #get the ticket id the attendee has typed
            ticket = Ticket.query.get(ticket_id)
            if ticket:
                db.session.delete(ticket) #remove the ticket from database
                db.session.commit()

                return redirect(url_for('dashboard'))

            else:
                error_message = "Cannot find your tickets" #no such ticket to be cancelled
                return render_template('cancel_ticket.html', error_message=error_message)
        else:
            return render_template('cancel_ticket.html')
    else:
        return redirect(url_for('login'))

def generate_passcode(): #method to create a passcode for email verification
    x = string.ascii_lowercase 
    otp = ''.join(random.choice(x) for _ in range(6))
    return otp

def send_email(recipient, subject, body): #method to send the email to emaisl
    email = Message(subject=subject, recipients=[recipient], sender='mo.dulla20@gmail.com')
    email.body = body
    mail.send(email)

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)
