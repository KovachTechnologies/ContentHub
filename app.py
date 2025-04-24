#!/usr/bin/python

###########################################################################
#
# name          : app.py
#
# purpose       : Serve web content for an LMS with SQLite-based user management
#
# usage         : python3 app.py
#
# description   : A Flask-based Learning Management System with user authentication
#                 and course content delivery. User data is stored in a SQLite database.
#
###########################################################################

import bcrypt
import json
import logging
import os

from flask import Flask, render_template, request, redirect, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'super_secret_key')  # Use env var in production
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize SQLAlchemy
db = SQLAlchemy(app)

# Load course data from JSON
with open("data/media.json", 'r') as f:
    courses = json.load(f)
course_content = [i["content"][0] for i in courses]

# Database Model for User
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    score = db.Column(db.Float, default=0.0)
    admin = db.Column(db.Boolean, default=False)
    group = db.Column(db.String(50), default='default')

    def set_password(self, password):
        """Hash and set the user's password."""
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
        """Verify the provided password against the stored hash."""
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))

# Create database tables
with app.app_context():
    db.create_all()

def get_admin():
    """Retrieve leaderboard data for users in the same group as the current user."""
    input_data = User.query.filter_by(group=session.get('group')).all()
    return get_leaderboard(input_data)

def get_leaderboard(input_data=None):
    """Generate leaderboard data sorted by score."""
    if input_data is None:
        input_data = User.query.all()
    leaderboard_data = sorted(input_data, key=lambda x: x.score, reverse=True)
    return [{'username': user.username, 'score': user.score, 'rank': i + 1} for i, user in enumerate(leaderboard_data)]

def calculate_score():
    """Calculate and update the user's score based on correct/incorrect answers."""
    try:
        correct = session.get('correct_answer', 0)
        incorrect = session.get('incorrect_answer', 0)
        total = correct + incorrect
        score = round(100 * (correct / total), 2) if total > 0 else 0.0
        user = User.query.filter_by(username=session['username']).first()
        user.score = score
        db.session.commit()
        logger.info(f"Score updated for {user.username}: {score}")
    except Exception as e:
        logger.error(f"Error calculating score: {str(e)}")

@app.route('/')
@app.route('/login')
def login():
    """Render the login page."""
    return render_template("login.html")

@app.route('/handle_login', methods=['POST'])
def handle_login():
    """Handle user login."""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['username'] = user.username
            session['admin'] = int(user.admin)
            session['group'] = user.group
            logger.info(f"User {username} logged in successfully")
            return render_template("menu.html", data=courses, admin=session['admin'])
        else:
            logger.warning(f"Failed login attempt for username: {username}")
            return render_template("login_failure.html")

@app.route('/logout')
def logout():
    """Handle user logout."""
    username = session.get('username', 'unknown')
    session.clear()
    logger.info(f"User {username} logged out")
    return render_template("logout.html")

@app.route('/register')
def register():
    """Render the registration page."""
    return render_template("register.html", data={"error": ""})

@app.route('/handle_registration', methods=['POST'])
def handle_registration():
    """Handle new user registration."""
    username = request.form.get('username')
    password = request.form.get('password')
    email = request.form.get('email')

    if not all([username, password, email]):
        return render_template("register.html", data={"error": "All fields are required"})

    if User.query.filter_by(username=username).first():
        return render_template("register.html", data={"error": f"Username '{username}' taken"})
    
    if User.query.filter_by(email=email).first():
        return render_template("register.html", data={"error": f"Email '{email}' already registered"})

    try:
        new_user = User(username=username, email=email, group='default')
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        logger.info(f"New user registered: {username}")
        return render_template("login.html")
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error registering user {username}: {str(e)}")
        return render_template("register.html", data={"error": "Registration failed. Try again."})

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    """Render the change password page."""
    if request.method == 'POST':
        return render_template("change_password.html", data={"error": ""})
    return render_template("change_password.html", data={"error": ""})

@app.route('/handle_change_password', methods=['POST'])
def handle_change_password():
    """Handle password change."""
    old_password = request.form.get('oldpassword')
    new_password = request.form.get('password')
    username = session.get('username')

    user = User.query.filter_by(username=username).first()
    if not user:
        logger.error(f"User {username} not found during password change")
        return render_template("change_password.html", data={"error": "User not found"})

    if not user.check_password(old_password):
        logger.warning(f"Invalid old password for user {username}")
        return render_template("change_password.html", data={"error": "Old password does not match"})

    try:
        user.set_password(new_password)
        db.session.commit()
        logger.info(f"Password changed for user {username}")
        return render_template("profile.html", admin=session['admin'])
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error changing password for {username}: {str(e)}")
        return render_template("change_password.html", data={"error": "Password change failed"})

# Other routes (unchanged or minimally modified)
@app.route('/menu')
def menu():
    return render_template("menu.html", data=courses, admin=session.get('admin', 0))

@app.route('/content', methods=['POST'])
def content():
    if request.method == 'POST':

        # determine if the request came from javascript
        from_js = False
        try :
            res = request.get_json()
            if "fromJavascript" in res :
                from_js = True
        except :
            pass

        # get the video series id 
        if "vid" in request.form :
            vid = int( request.form[ "vid" ] )
            session[ "vid" ] = vid 
            session[ "sid" ] = 0
        elif "vid" in session :
            vid = int( session[ "vid" ] )
        else :
            print( "No vid :(" )
            return render_template( "menu.html", data=courses, admin=session[ "admin" ] )

        # get specific video id 
        if "sid" in session :
            sid = int( session[ "sid" ] )
        else :
            sid = 0

        # increment or decrement the series
        INC = "increment" in request.form
        try :
            INC |= "increment" in request.get_json() 
        except :
            pass

        DEC = "decrement" in request.form  
        try :
            DEC |= "decrement" in request.get_json() 
        except :
            pass

        # handle the incrementation, accounting for beginning and end
        if INC :
            if sid < len( course_content[ vid ] ) - 1  :
                sid += 1
            else :
                calculate_score()
        if DEC :
            if sid != 0 :
                sid -= 1
        session[ "sid" ] = sid

        # pop that thang
        session.pop( "increment", None )
        session.pop( "decrement", None )

        content = copy.deepcopy( course_content[ vid ][ sid ] )

        if from_js :
            content.pop( "a", None )
            return content
        else :
            return render_template( "content.html", data=content, admin=session[ "admin" ] )


@app.route('/evaluate_answer', methods=['POST'] )
def evaluate_answer():
    try :
        res = request.get_json() 
    except :
        pass

    if "incorrect_answer" not in session :
        session[ "incorrect_answer" ] = 0
    if "correct_answer" not in session :
        session[ "correct_answer" ] = 0

    vid = session[ "vid" ]
    sid = session[ "sid" ]
    correct = course_content[ vid ][ sid ][ "a" ]

    if correct == res[ "answer" ] :
        session[ "correct_answer" ] += 1
        return_value = True 
    else :
        session[ "incorrect_answer" ] += 1
        return_value = False
    
    #return jsonify( answer=return_value ) 
    return { "answer": return_value } 


@app.route('/leaderboard')
def leaderboard():
    return render_template("leaderboard.html", data=get_leaderboard(), admin=session.get('admin', 0))

@app.route('/clear_score')
def clear_score():
    return render_template("profile.html", admin=session.get('admin', 0))

@app.route('/profile')
def profile():
    return render_template("profile.html", admin=session.get('admin', 0))

@app.route('/admin')
def admin():
    if session.get('admin') == 1:
        return render_template("admin.html", data=get_admin(), admin=session['admin'])
    return render_template("leaderboard.html", data=get_leaderboard(), admin=session.get('admin', 0))

if __name__ == '__main__':
    app.run(debug=True, port=5001)
