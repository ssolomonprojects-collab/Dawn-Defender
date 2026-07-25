from flask import Blueprint, render_template, redirect, url_for
from flask_login import login_required, current_user

from app.models import ScanHistory

main_bp = Blueprint("main", __name__)


@main_bp.route("/")
def index():
    try:
        if current_user.is_authenticated:
            return redirect(url_for("main.dashboard"))
    except Exception:
        pass
    return render_template("index.html")


@main_bp.route("/dashboard")
@login_required
def dashboard():
    try:
        recent_scans = (
            ScanHistory.query.filter_by(user_id=current_user.id)
            .order_by(ScanHistory.created_at.desc())
            .limit(10)
            .all()
        )
    except Exception as e:
        print(f"Dashboard scan history query notice: {e}")
        recent_scans = []
    return render_template("main/dashboard.html", recent_scans=recent_scans)
