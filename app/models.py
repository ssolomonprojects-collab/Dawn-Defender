"""
Two tables: User (essential registration fields only) and ScanHistory
(one row per scan, linked to whichever user ran it).
"""
from datetime import datetime, timezone, timedelta
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

from app import db

IST = timezone(timedelta(hours=5, minutes=30))


def _now_ist():
    return datetime.now(IST).replace(tzinfo=None)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=_now_ist)

    scans = db.relationship("ScanHistory", backref="user", lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class ScanHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    scan_type = db.Column(db.String(20), nullable=False)      # url | sms | email
    content_preview = db.Column(db.String(300), nullable=False)

    risk_score = db.Column(db.Integer, nullable=False)
    verdict = db.Column(db.String(20), nullable=False)         # safe | suspicious | dangerous
    red_flags = db.Column(db.Text, nullable=False)
    explanation = db.Column(db.Text, nullable=False)
    recommendation = db.Column(db.Text, nullable=False)

    created_at = db.Column(db.DateTime, default=_now_ist)

    def red_flags_list(self):
        return [f for f in self.red_flags.split("||") if f]

    def formatted_time(self):
        return self.created_at.strftime("%d %b %Y, %I:%M %p IST")
