import os
import sqlite3
import time
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, g, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash

# ---------- App and Logger Configuration ----------
app = Flask(__name__)
app.secret_key = "vinit"  # In production, this should be a more complex, secret value

# Configure logger
logger = logging.getLogger("auth_logger")
logger.setLevel(logging.INFO)

# Use an absolute path to ensure the log file is created in the script's directory
basedir = os.path.abspath(os.path.dirname(__file__))
log_file_path = os.path.join(basedir, 'auth_services.log')

file_handler = RotatingFileHandler(log_file_path, maxBytes=1*1024*1024, backupCount=5)
file_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
logger.addHandler(file_handler)

# Test log message on startup
logger.info("Application starting up...")

# ---------- Database Setup ----------
def vinitdatabase():
    """Initializes the database and creates the students table if it doesn't exist."""
    with sqlite3.connect("Student.db") as conn:
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS students (
                            username TEXT PRIMARY KEY,
                            password TEXT NOT NULL)''')
        conn.commit()

# ---------- Secure Authentication Functions ----------
def authenticate(username, password):
    """Verifies a user's credentials against the database."""
    user_hash = None
    with sqlite3.connect("Student.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM students WHERE username=?", (username,))
        user_hash = cursor.fetchone()
    
    if user_hash and check_password_hash(user_hash[0], password):
        return True
    return False

def adduser(username, password):
    """Adds a new user to the database with a hashed password."""
    hashed_password = generate_password_hash(password)
    try:
        with sqlite3.connect("Student.db") as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO students (username, password) VALUES (?, ?)", (username, hashed_password))
            conn.commit()
        return True
    except sqlite3.IntegrityError:
        # This error means the username already exists
        return False

# ---------- Input Validation ----------
def checkpw(password):
    """Validates password strength and returns a list of errors."""
    errors = []
    if password.isalnum():
        errors.append("Include at least one symbol.")
    if password.islower():
        errors.append("Include at least one UPPERCASE letter.")
    if password.isupper():
        errors.append("Include at least one lowercase letter.")
    if not (8 <= len(password) <= 16):
        errors.append("Password must be 8–16 characters long.")
    if any(char.isspace() for char in password):
        errors.append("Password must not contain spaces.")
    if not any(char.isdigit() for char in password):
        errors.append("Password must include at least one number.")
    return (len(errors) == 0, errors)

def checkusername(username):
    """Validates username format and returns a list of errors."""
    errors = []
    if any(char.isspace() for char in username):
        errors.append("Username must not contain spaces.")
    if not username.isalnum():
        errors.append("Username must only contain letters and numbers.")
    if username.isdigit():
        errors.append("Username cannot be only numbers.")
    if len(username) < 3:
        errors.append("Username must be at least 3 characters long.")
    return (len(errors) == 0, errors)

# ---------- Request Timing and Logging ----------
@app.before_request
def before_request_logging():
    """Store the start time of a request."""
    g.start_time = time.time()

@app.after_request
def after_request_logging(response):
    """Log the time taken to process a request."""
    if 'start_time' in g:
        duration = time.time() - g.start_time
        logger.info(f"Request to {request.path} took {duration:.4f} seconds")
    return response

# ---------- Routes ----------
@app.route("/")
def home():
    if "username" in session:
        return f"Welcome {session['username']}! <a href='/logout'>Logout</a>"
    return redirect(url_for("login"))

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        valid_user, user_errors = checkusername(username)
        if not valid_user:
            logger.warning(f"Signup failed for '{username}': Validation errors {user_errors}")
            for e in user_errors:
                flash(e, "danger")
            return render_template("signup.html")
        
        valid_pw, pw_errors = checkpw(password)
        if not valid_pw:
            logger.warning(f"Signup failed for '{username}': Password errors {pw_errors}")
            for e in pw_errors:
                flash(e, "danger")
            return render_template("signup.html")

        if adduser(username, password):
            flash("Signup successful! Please login.", "success")
            logger.info(f"New user '{username}' signed up successfully.")
            return redirect(url_for("login"))
        else:
            flash("Username already exists.", "danger")
            logger.warning(f"Signup failed: Username '{username}' already exists.")
            return render_template("signup.html")
    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        if authenticate(username, password):
            session["username"] = username
            flash("Login successful!", "success")
            logger.info(f"User '{username}' logged in successfully.")
            return redirect(url_for("home"))
        else:
            flash("Invalid username or password", "danger")
            logger.warning(f"Failed login attempt for username '{username}'")
            return render_template("login.html")
    return render_template("login.html")

@app.route("/logout")
def logout():
    # Log the logout event before clearing the session
    if 'username' in session:
        logger.info(f"User '{session['username']}' logged out.")
        session.pop("username", None)
    
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))

# ---------- Main Execution Block ----------
if __name__ == "__main__":
    vinitdatabase()
    app.run(debug=True)
