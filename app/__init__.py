"""
App factory. Creates the Flask app, sets up the database, login manager,
and registers each feature as its own blueprint (auth, main, scan) - so
each "page" genuinely lives in its own file, per your requirement.
"""
import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

db = SQLAlchemy()
login_manager = LoginManager()


def create_app():
    app = Flask(__name__)

    basedir = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-this")
    db_path = os.path.join(basedir, "instance", "dawn_defender.db")
    if not os.path.exists(db_path) and os.path.exists(os.path.join(basedir, "instance", "sentinel.db")):
        db_path = os.path.join(basedir, "instance", "sentinel.db")
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + db_path
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["UPLOAD_FOLDER"] = os.path.join(basedir, "app", "static", "uploads")
    app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5MB max upload (QR images)

    os.makedirs(os.path.join(basedir, "instance"), exist_ok=True)
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

    db.init_app(app)

    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message = "Please log in to use the scanner."

    from app.models import User

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    from app.auth.routes import auth_bp
    from app.main.routes import main_bp
    from app.scan.routes import scan_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(scan_bp)

    with app.app_context():
        db.create_all()

    return app
