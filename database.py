from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_login import UserMixin

db = SQLAlchemy()
bcrypt = Bcrypt()
login_manager = LoginManager()
login_manager.login_view = 'login'


class User(db.Model, UserMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

    privilege_id = db.Column(db.Integer, db.ForeignKey('privileges.id'), nullable=False)
    privilege = db.relationship('Privilege', backref='users')


class Privilege(db.Model):
    __tablename__ = 'privileges'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
