"""
Registration collects essentials: username, email, password, and 4-digit Safety PIN.
"""
from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user

from app import db
from app.models import User

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm", "")
        safety_pin = request.form.get("safety_pin", "").strip()

        error = None
        if not username or not email or not password or not safety_pin:
            error = "All fields including 4-digit Safety PIN are required."
        elif len(password) < 6:
            error = "Password must be at least 6 characters."
        elif len(safety_pin) != 4 or not safety_pin.isdigit():
            error = "Safety PIN must be exactly 4 digits (e.g. 1234)."
        elif password != confirm_password:
            error = "Passwords don't match."
        elif User.query.filter_by(username=username).first():
            error = "That username is already taken."
        elif User.query.filter_by(email=email).first():
            error = "An account with that email already exists."

        if error:
            flash(error, "error")
            return render_template("auth/register.html", username=username, email=email)

        user = User(username=username, email=email)
        user.set_password(password)
        user.set_safety_pin(safety_pin)
        db.session.add(user)
        db.session.commit()

        # remember=True writes a persistent cookie so the session survives page navigations on HTTPS
        login_user(user, remember=True)
        session.permanent = True
        flash("Account created with Privacy Safety PIN enabled. Welcome to Dawn Defender.", "success")
        return redirect(url_for("main.dashboard"))

    return render_template("auth/register.html")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter(
            (User.username == username) | (User.email == username.lower())
        ).first()

        if user and user.check_password(password):
            # remember=True writes a persistent cookie so the session survives page navigations on HTTPS
            login_user(user, remember=True)
            session.permanent = True
            next_page = request.args.get("next")
            return redirect(next_page or url_for("main.dashboard"))

        flash("Incorrect username/email or password.", "error")
        return render_template("auth/login.html", username=username)

    return render_template("auth/login.html")


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You've been logged out.", "success")
    return redirect(url_for("auth.login"))
