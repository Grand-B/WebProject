from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user

from database import db, bcrypt, login_manager, User

app = Flask(__name__, template_folder="webpage")
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://grandadmin:Rb1of2jp3jd1!123@localhost:9308/webdb'
app.config['SECRET_KEY'] = 'GRANDFANTASIA!123'

#Initialize the database
db.init_app(app)
bcrypt.init_app(app)
login_manager.init_app(app)

@app.route("/")
def home():
    return render_template("web.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

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
def login():
    username = request.form["username"]
    password = request.form["password"]

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


if __name__ == "__main__":
    app.run(debug=True)
