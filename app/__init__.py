from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_material import Material
from config import Config

db = SQLAlchemy()
login_manager = LoginManager()
migrate = Migrate()
material = Material()

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    migrate.init_app(app, db)
    material.init_app(app)

    from app.routes import auth_bp, admin_bp, courses_bp, enquiries_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(courses_bp)
    app.register_blueprint(enquiries_bp)

    return app

@login_manager.user_loader
def load_user(user_id):
    from app.models.user import User
    return User.query.get(int(user_id))