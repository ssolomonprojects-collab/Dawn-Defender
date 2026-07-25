"""
App factory. Creates the Flask app, sets up the database, login manager,
and registers each feature as its own blueprint (auth, main, scan).
Production deployment ready for Vercel, Supabase PostgreSQL, Render, and Railway.
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
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-dawn-defender-hackathon-2026")
    
    # 1. Database URI configuration (Supports Supabase PostgreSQL & Safe Vercel /tmp Fallback)
    db_uri = os.environ.get("DATABASE_URL") or os.environ.get("SUPABASE_DB_URL")
    if db_uri and "[YOUR-PASSWORD]" not in db_uri and "YOUR-PASSWORD" not in db_uri:
        if db_uri.startswith("postgres://"):
            db_uri = db_uri.replace("postgres://", "postgresql://", 1)
        app.config["SQLALCHEMY_DATABASE_URI"] = db_uri
    else:
        if os.getenv("VERCEL"):
            app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:////tmp/dawn_defender.db"
        else:
            db_path = os.path.join(basedir, "instance", "dawn_defender.db")
            if not os.path.exists(db_path) and os.path.exists(os.path.join(basedir, "instance", "sentinel.db")):
                db_path = os.path.join(basedir, "instance", "sentinel.db")
            app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + db_path

    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    
    # Configure upload directory safely for Vercel (/tmp) vs Local
    if os.getenv("VERCEL"):
        app.config["UPLOAD_FOLDER"] = "/tmp/uploads"
    else:
        app.config["UPLOAD_FOLDER"] = os.path.join(basedir, "app", "static", "uploads")

    app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5MB max upload

    # Create directories safely (handles Vercel read-only filesystem)
    try:
        if not os.getenv("VERCEL"):
            os.makedirs(os.path.join(basedir, "instance"), exist_ok=True)
        os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    except OSError:
        pass

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

    @app.after_request
    def add_no_cache_headers(response):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "-1"
        return response

    with app.app_context():
        try:
            db.create_all()
        except Exception as e:
            print(f"Database table initialization notice: {e}")

    return app
