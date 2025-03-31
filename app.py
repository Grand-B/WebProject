import re
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from database import db, bcrypt, login_manager, User, Privilege, Feedback

app = Flask(__name__, template_folder="webpage")
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://grandadmin:Rb1of2jp3jd1!123@localhost:9308/webdb'
app.config['SECRET_KEY'] = 'GRANDFANTASIA!123'

#Initializing the database and bcrypt
db.init_app(app)
bcrypt.init_app(app)
login_manager.init_app(app)

#Rate limiting the amount of requests to the server
#Brute Force Prevention
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "20 per minutes"] 
)

#Input authentication
def validInput(value):
    return re.fullmatch(r"[a-zA-Z0-9_@$!.-]{3,32}", value)

#Password strength check
def strongPass(password):
    return (
        len(password) >= 8 and
        re.search("[a-z]", password) and
        re.search("[A-Z]", password) and
        re.search("[0-9]", password) and
        re.search("[!$@_.]", password)
    )

#Default home page
@app.route("/")
def home():
    return render_template("web.html")

#register page
@app.route("/register", methods=["GET", "POST"])
@limiter.limit("50 per minutes")
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        if not validInput(username) or not validInput(password):
            flash("Invalid characters in username or password.", "danger")
            return redirect(url_for("register"))

        if not strongPass(password):
            flash("Password must contain at least 8 characters, one uppercase, one lowercase, one number and one special character (! $ @ _ .)", "danger")
            return redirect(url_for("register"))

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash("Username already exists. Please log in.", "danger")
            return redirect(url_for("home"))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        default_privilege = Privilege.query.filter_by(name='user').first()
        if not default_privilege:
            flash("Default user role not found in the database.", "danger")
            return redirect(url_for("register"))

        new_user = User(
            username=username,
            password=hashed_password,
            privilege=default_privilege
        )
        db.session.add(new_user)
        db.session.commit()

        flash("Account created successfully! You can now log in.", "success")
        return redirect(url_for("home"))

    return render_template("register.html")

#login function itself
@app.route("/login", methods=["POST"])
#rate limiting the amount of times the user can login
@limiter.limit("20 per minute")
def login():
    username = request.form["username"]
    password = request.form["password"]

    if not validInput(username) or not validInput(password):
        flash("Invalid characters in username or password.", "danger")
        return redirect(url_for("home"))

    user = User.query.filter_by(username=username).first()
    if user and bcrypt.check_password_hash(user.password, password):
        login_user(user)
        flash("Login successful!", "success")
        return redirect(url_for("dashboard"))
    else:
        flash("Invalid username or password", "danger")
        return redirect(url_for("home"))

#back to previous page button
@app.route("/backbutton")
def back():
    return render_template("web.html")

#home page after logging in 
@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("loggedIn.html", username=current_user.username)

#logout function, leads to home page
@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have logged out.", "info")
    return redirect(url_for("home"))

#Change password page
@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        current = request.form["currentPassword"]
        new = request.form["newPassword"]

        if not validInput(current) or not validInput(new):
            flash("Invalid characters in password, try again.", "danger")
            return redirect(url_for("change_password"))

        if not bcrypt.check_password_hash(current_user.password, current):
            flash("Current password incorrect", "danger")
            return redirect(url_for("change_password"))

        if not strongPass(new):
            flash("New password must contain at least 8 characters, one uppercase, one lowercase, one number and one special character (! $ @ _ .)", "danger")
            return redirect(url_for("change_password"))

        new_hashed = bcrypt.generate_password_hash(new).decode("utf-8")
        current_user.password = new_hashed
        db.session.commit()
        flash("Password updated successfully!", "success")
        return redirect(url_for("change_password"))

    return render_template("changePassword.html")

#feedback input box
@app.route("/submit-feedback", methods=["POST"])
@login_required
def submit_feedback():
    feedback_text = request.form.get("feedback", "").strip()

    if len(feedback_text) < 5:
        flash("Feedback is too short or empty.", "warning")
        return redirect(url_for("dashboard"))

    new_feedback = Feedback(
        user_id=current_user.id,
        content=feedback_text
    )

    db.session.add(new_feedback)
    db.session.commit()

    flash("Thanks for your feedback!", "success")
    return redirect(url_for("dashboard"))

if __name__ == "__main__":
    app.run(debug=True)
