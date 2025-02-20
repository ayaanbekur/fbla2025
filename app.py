from flask import Flask, render_template, request, redirect, url_for, flash, session
import json
import os
from datetime import datetime
import hashlib
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

# File to store user data
USER_DATA_FILE = "user_data.json"

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

# Register a new user
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        user_data = load_user_data()
        if username in user_data:
            flash("Username already exists. Please log in.", "error")
            return redirect(url_for("register"))

        user_data[username] = {
            "password": hash_password(password),
            "balance": 0,
            "transactions": [],
            "goals": [],
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        save_user_data(user_data)
        flash("Registration successful! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

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

        return render_template("summary.html", transactions=filtered_transactions, period=period)

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
@app.route("/account_settings")
def account_settings():
    if "username" not in session:
        flash("Please log in to access account settings.", "error")
        return redirect(url_for("login"))

    username = session["username"]
    user_data = load_user_data()
    user = user_data[username]

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

if __name__ == "__main__":
    app.run(debug=True)