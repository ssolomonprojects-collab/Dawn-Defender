"""
Three scan pages: URL, SMS, Email. Each follows the same pattern —
run heuristics, run the trained model, combine into a verdict via
decision.build_verdict(), save to history, show the result page.
"""
import os
from flask import Blueprint, render_template, request, flash
from flask_login import login_required, current_user

from app import db
from app.models import ScanHistory
from app.ml import heuristics, decision, url_model, sms_model, email_model

scan_bp = Blueprint("scan", __name__)


def _save_scan(scan_type, content_preview, result):
    record = ScanHistory(
        user_id=current_user.id,
        scan_type=scan_type,
        content_preview=content_preview[:300],
        risk_score=result["risk_score"],
        verdict=result["verdict"],
        red_flags="||".join(result["red_flags"]),
        explanation=result["explanation"],
        recommendation=result["recommendation"],
    )
    db.session.add(record)
    db.session.commit()


@scan_bp.route("/scan/url", methods=["GET", "POST"])
@login_required
def scan_url():
    if request.method == "POST":
        url = request.form.get("url", "").strip()
        if not url:
            flash("Please enter a URL to scan.", "error")
            return render_template("scan/scan_url.html")

        h = heuristics.analyze_url(url)
        m = url_model.predict(url)
        result = decision.build_verdict("url", h["flags"], h["score_hint"], m["confidence"], m["model_used"])

        print(f"\n[URL SCAN] '{url}' -> Risk: {result['risk_score']} ({result['verdict'].upper()})")

        _save_scan("url", url, result)
        return render_template("scan/result.html", result=result, scan_type="URL", content=url)

    return render_template("scan/scan_url.html")


@scan_bp.route("/scan/sms", methods=["GET", "POST"])
@login_required
def scan_sms():
    if request.method == "POST":
        text = request.form.get("text", "").strip()
        if not text:
            flash("Please enter a message to scan.", "error")
            return render_template("scan/scan_sms.html")

        h = heuristics.analyze_text(text)
        m = sms_model.predict(text)
        result = decision.build_verdict("sms", h["flags"], h["score_hint"], m["confidence"], m["model_used"])

        print(f"\n[SMS SCAN] '{text[:40]}' -> Risk: {result['risk_score']} ({result['verdict'].upper()})")

        _save_scan("sms", text, result)
        return render_template("scan/result.html", result=result, scan_type="SMS", content=text)

    return render_template("scan/scan_sms.html")


@scan_bp.route("/scan/email", methods=["GET", "POST"])
@login_required
def scan_email():
    if request.method == "POST":
        text = request.form.get("text", "").strip()
        if not text:
            flash("Please paste an email to scan.", "error")
            return render_template("scan/scan_email.html")

        h = heuristics.analyze_text(text)
        m = email_model.predict(text)
        result = decision.build_verdict("email", h["flags"], h["score_hint"], m["confidence"], m["model_used"])

        print(f"\n[EMAIL SCAN] '{text[:40]}' -> Risk: {result['risk_score']} ({result['verdict'].upper()})")

        _save_scan("email", text, result)
        return render_template("scan/result.html", result=result, scan_type="Email", content=text[:200])

    return render_template("scan/scan_email.html")


@scan_bp.route("/history")
@login_required
def history():
    scans = (
        ScanHistory.query.filter_by(user_id=current_user.id)
        .order_by(ScanHistory.created_at.desc())
        .all()
    )
    return render_template("scan/history.html", scans=scans)
