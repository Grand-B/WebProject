from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user

from database import db, bcrypt, login_manager, User
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import re


app = Flask(__name__, template_folder="webpage")
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://grandadmin:Rb1of2jp3jd1!123@localhost:9308/webdb'
app.config['SECRET_KEY'] = 'GRANDFANTASIA!123'

#Initialize the database
db.init_app(app)
bcrypt.init_app(app)
login_manager.init_app(app)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per day", "20 per hour"] #bans you after these limits lol
)

def is_valid_input(value):
    return re.fullmatch(r"[a-zA-Z0-9_@.-]{3,32}", value)

@app.route("/")
def home():
    return render_template("web.html")

@app.route("/register", methods=["GET", "POST"])
@limiter.limit("10 per hour") #Limit the registration attempts to 10 per hour
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        if not is_valid_input(username) or not is_valid_input(password):
            flash("Invalid characters in username or password.", "danger")
            return redirect(url_for("register"))
        
        flag = 0
        while True:
            if (len(password)<=8):
                flag = -1
                break
            elif not re.search("[a-z]", password):
                flag = -1
                break
            elif not re.search("[A-Z]", password):
                flag = -1
                break
            elif not re.search("[0-9]", password):
                flag = -1
                break
            elif not re.search("[_@$]" , password):
                flag = -1
                break
            else:
                flag = 0
                print("Valid Password")
                break

        if flag == -1:
            print("Not a Valid Password ")
            flash("Password must contain at least 8 characters, one uppercase, one lowercase, one number and one special character.", "danger")
            return redirect(url_for("register"))
        
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash("Username already exists. Please log in.", "danger")
            return redirect(url_for("home"))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash("Account created successfully! You can now log in.", "success")
        return redirect(url_for("home"))

    return render_template("register.html")

@app.route("/login", methods=["POST"])
@limiter.limit("5 per minute") #Limit the login attempts to 5 per minute
def login():
    username = request.form["username"]
    password = request.form["password"]

    if not is_valid_input(username) or not is_valid_input(password):
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

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("loggedIn.html", username=current_user.username)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have logged out.", "info")
    return redirect(url_for("home"))

@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        current = request.form["currentPassword"]
        new = request.form["newPassword"]

        if bcrypt.check_password_hash(current_user.password, current):
            new_hashed = bcrypt.generate_password_hash(new).decode("utf-8")
            current_user.password = new_hashed
            db.session.commit()
            flash("Password updated successfully.", "success")
        else:
            flash("Incorrect current password.", "danger")
        return redirect(url_for("change_password"))

    return render_template("changePassword.html")

if __name__ == "__main__":
    app.run(debug=True)
