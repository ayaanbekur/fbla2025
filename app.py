from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify #all of the libraries that we need to use
import json
import os
from datetime import datetime, timedelta
import hashlib
from dotenv import load_dotenv
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
import re
import openai
import requests
from flask_dance.contrib.google import make_google_blueprint
from flask_dance.consumer import oauth_authorized, oauth_error
from flask_dance.consumer.storage.sqla import SQLAlchemyStorage
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from openai import OpenAI
import json
from llamaapi import LlamaAPI
 
# Load environment variables
load_dotenv()

OPENROUTER_API_KEY = "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"
OPENROUTER_API_URL = "https://openrouter.ai/api/v1/chat/completions" # OpenRouter API endpoint
# Alpha Vantage API key
ALPHA_VANTAGE_API_KEY = os.getenv("ALPHA_VANTAGE_API_KEY")
  
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")
# Flask-Mail configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv("MAIL_USERNAME")
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")
app.config['MAIL_DEFAULT_SENDER'] = os.getenv("MAIL_USERNAME")

mail = Mail(app)

serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

USER_DATA_FILE = "user_data.json"

# Ensure environment variables are loaded
if not app.secret_key or not os.getenv("GOOGLE_CLIENT_ID") or not os.getenv("GOOGLE_CLIENT_SECRET"):
    raise ValueError("Missing environment variables. Please check your .env file.")

# Database setup for OAuth
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///oauth.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

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
    storage=SQLAlchemyStorage(User, db.session, user_id=lambda: session.get("user_id"))
)
app.register_blueprint(google_blueprint, url_prefix="/login/google")

@app.route("/chat_page")
def chat_page():
    if "username" not in session:
        flash("Please log in to access the chat.", "error")
        return redirect(url_for("login"))

    # Load user data and chat history
    username = session["username"]
    user_data = load_user_data()
    user = user_data.get(username, {})
    chat_history = user.get("chat_history", [])

    return render_template("chat.html", chat_history=chat_history)

  
@app.route("/chat", methods=["POST"])
def chat():
    if "username" not in session:
        return jsonify({"response": "Error: User not logged in."}), 401

    try:
        user_message = request.json.get("message", "")

        if not user_message:
            return jsonify({"response": "Error: No message provided."}), 400

        # Load user data
        username = session["username"]
        user_data = load_user_data()
        user = user_data.get(username, {})

        # Add user message to chat history
        if "chat_history" not in user:
            user["chat_history"] = []
        user["chat_history"].append({"role": "user", "content": user_message})

        # Prepare payload for the AI
        payload = {
    "model": "google/gemini-2.0-flash-lite-preview-02-05:free",
    "contents": "You are an ai, very smart, and updated in 2025, 03/12/2025. You are a financial advisor, and you are here to help me with users financial problems.",
    "messages": user["chat_history"],
    "temperature": 0.7,  # Adjust as needed
    "format": "markdown"  # <-- Tell the AI to use markdown-style formatting
}
 

        headers = {
            "Authorization": f"Bearer {OPENROUTER_API_KEY}",
            "Content-Type": "application/json"
        }

        # Send request to the AI
        response = requests.post(OPENROUTER_API_URL, json=payload, headers=headers)

        if response.status_code != 200:
            print(f"API Error {response.status_code}: {response.text}")
            return jsonify({"response": f"Error: {response.status_code} - {response.text}"}), 500

        # Extract AI response
        result = response.json()
        print("API Raw Response:", result)  # Log raw response for debugging

        if "choices" in result and result["choices"]:
            message_obj = result["choices"][0].get("message", {})
            ai_response = message_obj.get("content", "").strip()
        else:
            ai_response = "Unexpected response format from the AI."

        # Add AI response to chat history
        user["chat_history"].append({"role": "assistant", "content": ai_response})

        # Save updated user data
        user_data[username] = user
        save_user_data(user_data)

        print("Extracted AI Response:", ai_response)  # Debugging output

        return jsonify({"response": ai_response})

    except Exception as e:
        print(f"Server Error: {e}")
        return jsonify({"response": f"Error: {str(e)}"}), 500



    
def load_user_data():
    if not os.path.exists(USER_DATA_FILE):
        with open(USER_DATA_FILE, "w") as file:
            json.dump({}, file)
        return {}

    try:
        with open(USER_DATA_FILE, "r") as file:
            return json.load(file)
    except json.JSONDecodeError:
        with open(USER_DATA_FILE, "w") as file:
            json.dump({}, file)
        return {}

def save_user_data(data):
    with open(USER_DATA_FILE, "w") as file:
        json.dump(data, file, indent=4)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()
 
@app.route("/")
def home():
    return render_template("home.html")
  
# OAuth authorized handler
@oauth_authorized.connect_via(google_blueprint)
def google_authorized(blueprint, token):
    if not token:
        flash("Failed to log in with Google.", "error")
        return False

    resp = blueprint.session.get("https://www.googleapis.com/oauth2/v1/userinfo")
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
        db.session.add(user)
        db.session.commit()


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



# Password Reset Request
@app.route("/reset_password", methods=["GET", "POST"])
def reset_password():
    if request.method == "POST":
        email = request.form.get("email")
        user_data = load_user_data()
        user = next((u for u in user_data.values() if u.get("email") == email), None)

        if user:
            # Generate a reset token
            token = serializer.dumps(email, salt="password-reset")
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

    # Calculate total income and expenses
    total_income = 0
    total_expenses = 0

    for transaction in user.get("transactions", []):
        if transaction["type"] == "Income":
            total_income += transaction["amount"]
        else:
            total_expenses += transaction["amount"]

    return render_template("dashboard.html", user=user, total_income=total_income, total_expenses=total_expenses)
  
@app.route("/stocks")
def stocks():
    # Get the search query from the URL
    symbol = request.args.get("symbol", "").upper()

    # Default list of stock symbols to display if no search query
    stock_symbols = ["AAPL", "GOOGL", "MSFT", "AMZN", "TSLA", "NFLX", "META", "NVDA", "PYPL", "INTC"]

    # If a search query is provided, only fetch data for that symbol
    if symbol:
        stock_symbols = [symbol]

    # Fetch real-time stock data
    stock_data = []
    for symbol in stock_symbols:
        url = f"https://www.alphavantage.co/query?function=GLOBAL_QUOTE&symbol={symbol}&apikey={ALPHA_VANTAGE_API_KEY}"
        response = requests.get(url)
        data = response.json()

        if "Global Quote" in data:
            stock_info = data["Global Quote"]
            stock_data.append({
                "symbol": symbol,
                "price": stock_info.get("05. price", "N/A"),
                "change": stock_info.get("09. change", "N/A"),
                "change_percent": stock_info.get("10. change percent", "N/A")
            })
        else:
            print(f"Error fetching data for {symbol}: {data}")

    return render_template("stocks.html", stock_data=stock_data)

# Add income or expense
@app.route("/add_transaction", methods=["GET", "POST"])
def add_transaction():
    if "username" not in session:
        flash("Please log in to add a transaction.", "error")
        return redirect(url_for("login"))

    # Define the list of categories
    categories = [
        "Groceries", "Utilities", "Rent", "Entertainment", 
        "Transportation", "Savings", "Healthcare", "Education", 
        "Travel", "Other", "Income", "Salary", "Bonus", "Gift"
    ]

    if request.method == "POST":
        username = session["username"]
        user_data = load_user_data()
        user = user_data[username]

        # Get form data
        transaction_type = request.form.get("type").capitalize()
        category = request.form.get("category")
        amount = float(request.form.get("amount"))
        description = request.form.get("description")
        transaction_date = request.form.get("date")

        # Create transaction object
        transaction = {
            "date": transaction_date,
            "type": transaction_type,
            "category": category,
            "amount": amount,
            "description": description
        }

        # Add transaction to user's data
        user["transactions"].append(transaction)

        # Update balance
        if transaction_type == "Income":
            user["balance"] += amount
        else:
            user["balance"] -= amount

        # Save updated user data
        save_user_data(user_data)

        flash("Transaction added successfully!", "success")
        return redirect(url_for("dashboard"))

    # Pass the categories to the template
    return render_template("add_transaction.html", categories=categories)

 
# View all transactions
@app.route("/view_transactions")
def view_transactions():
    if "username" not in session:
        flash("Please log in to view transactions.", "error")
        return redirect(url_for("login"))

    username = session["username"]
    user_data = load_user_data()
    transactions = user_data[username].get("transactions", [])
    goals = user_data[username].get("goals", [])

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

    # Define categories
    categories = [
        "Groceries", "Utilities", "Rent", "Entertainment", 
        "Transportation", "Savings", "Healthcare", "Education", 
        "Travel", "Other"
    ]

    if request.method == "POST":
        period = request.form.get("period").capitalize()
        category = request.form.get("category")  # Get the selected category
        now = datetime.now()

        # Filter by period
        if period == "Weekly":
            start_date = now - timedelta(days=7)
        elif period == "Monthly":
            try:
                from dateutil.relativedelta import relativedelta
                start_date = now - relativedelta(months=1)
            except ImportError:
                flash("dateutil module is required for monthly summary.", "error")
                return redirect(url_for("summary"))
        else:
            flash("Invalid period.", "error")
            return redirect(url_for("summary"))

        # Filter transactions by date and category
        filtered_transactions = [
            t for t in transactions
            if datetime.strptime(t["date"], "%Y-%m-%d %H:%M:%S") >= start_date
            and (category == "All" or t["category"] == category)  # Filter by category
        ]

        return render_template("summary.html", transactions=filtered_transactions, period=period, categories=categories, selected_category=category, user=user_data[username])

    return render_template("summary.html", categories=categories, user=user_data[username])


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

    goal = goals[index]  # This is accessed, but we need to modify and save it.

    if request.method == "POST":
        amount = float(request.form.get("amount"))

        if amount <= 0:
            flash("Amount must be greater than 0.", "error")
        elif user_data[username]["balance"] < amount:
            flash("Insufficient balance to contribute.", "error")
        else:
            # Deduct from balance and add to the goal
            user_data[username]["balance"] -= amount
            goal["saved"] += amount
            save_user_data(user_data)  # Save changes to the file

            flash(f"Successfully contributed ${amount} to {goal['name']}!", "success")
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
        email = user.get("email")
        if email: 
            # Generate a reset token
            token = serializer.dumps(email, salt='password-reset')
            reset_url = url_for('reset_password_token', token=token, _external=True)
 
            # Send the reset email
            msg = Message("Password Reset Request",
                          recipients=[email])
            msg.body = f"To reset your password, visit the following link: {reset_url}"
            try:
                mail.send(msg)
                flash("A password reset link has been sent to your email.", "success")
            except Exception as e:
                print(f"Error sending email: {e}")
                flash("Failed to send the password reset link. Please try again later.", "error")
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
        email = serializer.loads(token, salt='password-reset', max_age=3600)
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