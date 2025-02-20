from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import json
import os
from datetime import datetime, timedelta
import hashlib
from dotenv import load_dotenv
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
import re
import flask_dance

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.consumer import oauth_authorized, oauth_error
from flask_dance.consumer.storage.sqla import SQLAlchemyStorage
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker

# Ensure environment variables are loaded
if not app.secret_key or not os.getenv("GOOGLE_CLIENT_ID") or not os.getenv("GOOGLE_CLIENT_SECRET"):
    raise ValueError("Missing environment variables. Please check your .env file.")

# Database setup for OAuth
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///oauth.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# db = SQLAlchemy(app)  # This line is redundant and should be removed

# Create engine and session
engine = create_engine(app.config['SQLALCHEMY_DATABASE_URI'])
db_session = scoped_session(sessionmaker(bind=engine))
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    google_id = db.Column(db.String(256), unique=True)
    email = db.Column(db.String(256), unique=True)

with app.app_context():
    db.create_all()
google_blueprint = make_google_blueprint(
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    scope=["profile", "email"],
    redirect_to="dashboard",
    storage=SQLAlchemyStorage(User, db_session, user_id=lambda: session.get("user_id"))
)
app.register_blueprint(google_blueprint, url_prefix="/login/google")

# OAuth authorized handler
@oauth_authorized.connect_via(google_blueprint)
def google_authorized(blueprint, token):
    if not token:
        flash("Failed to log in with Google.", "error")
        return False

    resp = blueprint.session.get("/oauth2/v1/userinfo")
    if not resp.ok:
        flash("Failed to fetch user info from Google.", "error")
        return False

    google_info = resp.json()
    google_id = google_info["id"]
    email = google_info["email"]

    # Check if the user already exists
    user = db_session.query(User).filter_by(google_id=google_id).first()
    if not user:
        user = User(google_id=google_id, email=email)
        db_session.add(user)
        db_session.commit()

    # Log the user in
    session["user_id"] = user.id
    session["google_token"] = token
    flash("Successfully logged in with Google.", "success")
    return False

# OAuth error handler
@oauth_error.connect_via(google_blueprint)
def google_error(blueprint, error, error_description=None, error_uri=None):
    flash(f"OAuth error from {blueprint.name}: {error}", "error")

# Email validation regex
def is_valid_email(email):
    pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    return re.match(pattern, email) is not None

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        email = request.form.get("email")

        # Validate email
        if not is_valid_email(email):
            flash("Invalid email address. Please enter a valid email.", "error")
            return redirect(url_for("register"))

        user_data = load_user_data()
        if username in user_data:
            flash("Username already exists. Please log in.", "error")
            return redirect(url_for("register"))

        user_data[username] = {
            "password": hash_password(password),
            "email": email,
            "balance": 0,
            "transactions": [],
            "goals": [],
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        save_user_data(user_data)
        flash("Registration successful! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

# Flask-Mail configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # Use Gmail's SMTP server
app.config['MAIL_PORT'] = 587  # Port for TLS
app.config['MAIL_USE_TLS'] = True  # Use TLS for security
app.config['MAIL_USERNAME'] = os.getenv("MAIL_USERNAME")  # Your email address
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")  # Your email password or app-specific password
app.config['MAIL_DEFAULT_SENDER'] = os.getenv("MAIL_USERNAME")  # Default sender email

mail = Mail(app)

# Token serializer for password reset
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# File to store user data
USER_DATA_FILE = "user_data.json"


# Password Reset Request
@app.route("/reset_password", methods=["GET", "POST"])
def reset_password():
    if request.method == "POST":
        email = request.form.get("email")
        user_data = load_user_data()
        user = next((u for u in user_data.values() if u.get("email") == email), None)

        if user:
            # Generate a reset token
            token = serializer.dumps(email, salt='password-reset')
            reset_url = url_for('reset_password_token', token=token, _external=True)

            # Send the reset email
            msg = Message("Password Reset Request",
                          recipients=[email])
            msg.body = f"To reset your password, visit the following link: {reset_url}"
            mail.send(msg)

            flash("A password reset link has been sent to your email.", "success")
            return redirect(url_for("login"))
        else:
            flash("No account found with that email address.", "error")

    return render_template("reset_password.html")

# Load user data from JSON file
def load_user_data():
    if not os.path.exists(USER_DATA_FILE):
        # Create the file with an empty JSON object
        with open(USER_DATA_FILE, "w") as file:
            json.dump({}, file)
        return {}

    try:
        with open(USER_DATA_FILE, "r") as file:
            return json.load(file)
    except json.JSONDecodeError:
        # If the file is empty or malformed, recreate it with an empty object
        with open(USER_DATA_FILE, "w") as file:
            json.dump({}, file)
        return {}

# Save user data to JSON file
def save_user_data(data):
    with open(USER_DATA_FILE, "w") as file:
        json.dump(data, file, indent=4)

# Hash passwords
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Home page
@app.route("/")
def home():
    return render_template("login.html")

# Log in an existing user
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        user_data = load_user_data()
        if username not in user_data or user_data[username]["password"] != hash_password(password):
            flash("Invalid username or password.", "error")
            return redirect(url_for("login"))

        session["username"] = username
        flash("Login successful!", "success")
        return redirect(url_for("dashboard"))

    return render_template("login.html")

# Dashboard
@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        flash("Please log in to access the dashboard.", "error")
        return redirect(url_for("login"))

    username = session["username"]
    user_data = load_user_data()
    user = user_data[username]

    return render_template("dashboard.html", user=user)

# Add income or expense
@app.route("/add_transaction", methods=["GET", "POST"])
def add_transaction():
    if "username" not in session:
        flash("Please log in to add a transaction.", "error")
        return redirect(url_for("login"))

    if request.method == "POST":
        username = session["username"]
        user_data = load_user_data()
        user = user_data[username]

        transaction_type = request.form.get("type").capitalize()
        category = request.form.get("category")
        amount = float(request.form.get("amount"))
        description = request.form.get("description")
        transaction_date = request.form.get("date")

        transaction = {
            "date": transaction_date,
            "type": transaction_type,
            "category": category,
            "amount": amount,
            "description": description
        }

        user["transactions"].append(transaction)
        if transaction_type == "Income":
            user["balance"] += amount
        else:
            user["balance"] -= amount

        save_user_data(user_data)
        flash("Transaction added successfully!", "success")
        return redirect(url_for("dashboard"))

    return render_template("add_transaction.html")

# View all transactions
@app.route("/view_transactions")
def view_transactions():
    if "username" not in session:
        flash("Please log in to view transactions.", "error")
        return redirect(url_for("login"))

    username = session["username"]
    user_data = load_user_data()
    transactions = user_data[username]["transactions"]

    return render_template("view_transactions.html", transactions=transactions)

# Add a savings goal
@app.route("/add_goal", methods=["GET", "POST"])
def add_goal():
    if "username" not in session:
        flash("Please log in to add a savings goal.", "error")
        return redirect(url_for("login"))

    if request.method == "POST":
        username = session["username"]
        user_data = load_user_data()
        user = user_data[username]

        goal_name = request.form.get("name")
        target_amount = float(request.form.get("target"))

        goal = {
            "name": goal_name,
            "target": target_amount,
            "saved": 0
        }

        user["goals"].append(goal)
        save_user_data(user_data)
        flash("Savings goal added successfully!", "success")
        return redirect(url_for("dashboard"))

    return render_template("add_goal.html")

# View savings goals
@app.route("/view_goals")
def view_goals():
    if "username" not in session:
        flash("Please log in to view savings goals.", "error")
        return redirect(url_for("login"))

    username = session["username"]
    user_data = load_user_data()
    goals = user_data[username]["goals"]

    return render_template("view_goals.html", goals=goals)

# Generate a summary
@app.route("/summary", methods=["GET", "POST"])
def summary():
    if "username" not in session:
        flash("Please log in to generate a summary.", "error")
        return redirect(url_for("login"))

    username = session["username"]
    user_data = load_user_data()
    transactions = user_data[username]["transactions"]

    if request.method == "POST":
        period = request.form.get("period").capitalize()
        now = datetime.now()

        if period == "Weekly":
            start_date = now.replace(day=now.day - 7)
        elif period == "Monthly":
            start_date = now.replace(month=now.month - 1)
        else:
            flash("Invalid period.", "error")
            return redirect(url_for("summary"))

        filtered_transactions = [
            t for t in transactions
            if datetime.strptime(t["date"], "%Y-%m-%d %H:%M:%S") >= start_date
        ]

        return render_template("summary.html", transactions=filtered_transactions, period=period, user=user_data[username])

    return render_template("summary.html")

# Edit or delete a transaction
@app.route("/edit_transaction/<int:index>", methods=["GET", "POST"])
def edit_transaction(index):
    if "username" not in session:
        flash("Please log in to edit a transaction.", "error")
        return redirect(url_for("login"))

    username = session["username"]
    user_data = load_user_data()
    transactions = user_data[username]["transactions"]

    if index < 0 or index >= len(transactions):
        flash("Invalid transaction index.", "error")
        return redirect(url_for("view_transactions"))

    if request.method == "POST":
        action = request.form.get("action")

        if action == "edit":
            transaction = transactions[index]
            transaction["type"] = request.form.get("type").capitalize()
            transaction["category"] = request.form.get("category")
            transaction["amount"] = float(request.form.get("amount"))
            transaction["description"] = request.form.get("description")
            flash("Transaction updated successfully!", "success")
        elif action == "delete":
            deleted_transaction = transactions[index]
            if deleted_transaction["type"] == "Income":
                user_data[username]["balance"] -= deleted_transaction["amount"]
            else:
                user_data[username]["balance"] += deleted_transaction["amount"]

            del transactions[index]
            flash("Transaction deleted successfully!", "success")
        else:
            flash("Invalid action.", "error")

        save_user_data(user_data)
        return redirect(url_for("view_transactions"))

    transaction = transactions[index]
    return render_template("edit_transaction.html", transaction=transaction, index=index)

# Contribute to a savings goal
@app.route("/contribute_to_goal/<int:index>", methods=["GET", "POST"])
def contribute_to_goal(index):
    if "username" not in session:
        flash("Please log in to contribute to a goal.", "error")
        return redirect(url_for("login"))

    username = session["username"]
    user_data = load_user_data()
    goals = user_data[username]["goals"]

    if index < 0 or index >= len(goals):
        flash("Invalid goal index.", "error")
        return redirect(url_for("view_goals"))

    goal = goals[index]

    if request.method == "POST":
        amount = float(request.form.get("amount"))

        if amount <= 0:
            flash("Amount must be greater than 0.", "error")
        elif user_data[username]["balance"] < amount:
            flash("Insufficient balance.", "error")
        else:
            # Deduct from balance and add to goal
            user_data[username]["balance"] -= amount
            goal["saved"] += amount
            save_user_data(user_data)
            flash(f"${amount:.2f} contributed to '{goal['name']}'.", "success")
            return redirect(url_for("view_goals"))

    return render_template("contribute_to_goal.html", goal=goal, index=index)

# Account Settings Page
@app.route("/account_settings", methods=["GET", "POST"])
def account_settings():
    if "username" not in session:
        flash("Please log in to access account settings.", "error")
        return redirect(url_for("login"))

    username = session["username"]
    user_data = load_user_data()
    user = user_data[username]

    if request.method == "POST":
        # Handle password reset request
        email = user.get("email")  # Get the user's email from their account data
        if email:
            # Generate a reset token
            token = serializer.dumps(email, salt='password-reset')
            reset_url = url_for('reset_password_token', token=token, _external=True)

            # Send the reset email
            msg = Message("Password Reset Request",
                          recipients=[email])
            msg.body = f"To reset your password, visit the following link: {reset_url}"
            mail.send(msg)

            flash("A password reset link has been sent to your email.", "success")
            return redirect(url_for("account_settings"))
        else:
            flash("No email address found for your account.", "error")

    return render_template("account_settings.html", user=user)

# Change Password
@app.route("/change_password", methods=["GET", "POST"])
def change_password():
    if "username" not in session:
        flash("Please log in to change your password.", "error")
        return redirect(url_for("login"))

    username = session["username"]
    user_data = load_user_data()

    if request.method == "POST":
        current_password = request.form.get("current_password")
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")

        if user_data[username]["password"] != hash_password(current_password):
            flash("Current password is incorrect.", "error")
        elif new_password != confirm_password:
            flash("New passwords do not match.", "error")
        else:
            user_data[username]["password"] = hash_password(new_password)
            save_user_data(user_data)
            flash("Password changed successfully!", "success")
            return redirect(url_for("account_settings"))

    return render_template("change_password.html")

# Delete Account
@app.route("/delete_account", methods=["GET", "POST"])
def delete_account():
    if "username" not in session:
        flash("Please log in to delete your account.", "error")
        return redirect(url_for("login"))

    username = session["username"]
    user_data = load_user_data()

    if request.method == "POST":
        confirm_username = request.form.get("confirm_username")

        if confirm_username != username:
            flash("Username does not match.", "error")
        else:
            del user_data[username]
            save_user_data(user_data)
            session.pop("username", None)
            flash("Your account has been deleted.", "success")
            return redirect(url_for("login"))

    return render_template("delete_account.html")

# Logout
@app.route("/logout")
def logout():
    session.pop("username", None)
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))

# Reset Password Token
@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password_token(token):
    try:
        email = serializer.loads(token, salt='password-reset', max_age=3600)  # Token expires in 1 hour
    except:
        flash("The reset link is invalid or has expired.", "error")
        return redirect(url_for("reset_password"))

    if request.method == "POST":
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")

        if new_password != confirm_password:
            flash("Passwords do not match.", "error")
        else:
            user_data = load_user_data()
            user = next((u for u in user_data.values() if u.get("email") == email), None)
            if user:
                user["password"] = hash_password(new_password)
                save_user_data(user_data)
                flash("Your password has been reset.", "success")
                return redirect(url_for("login"))
            else:
                flash("User not found.", "error")
    return render_template("reset_password_token.html", token=token)

@app.teardown_appcontext
def shutdown_session(exception=None):
    db_session.remove()

if __name__ == "__main__":
    app.run(debug=True)