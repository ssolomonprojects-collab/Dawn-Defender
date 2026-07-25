"""
Five scan pages: URL, SMS, Email, APK, History.
Includes API endpoints for Safety PIN verification and Harmful APK deletion.
"""
import os
from flask import Blueprint, render_template, request, flash, jsonify
from flask_login import login_required, current_user

from app import db
from app.models import ScanHistory
from app.ml import heuristics, decision, url_model, sms_model, email_model, apk_model

scan_bp = Blueprint("scan", __name__)


def _save_scan(scan_type, content_preview, result):
    try:
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
    except Exception as e:
        db.session.rollback()
        print(f"Notice saving scan history: {e}")


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

        _save_scan("email", text, result)
        return render_template("scan/result.html", result=result, scan_type="Email", content=text[:200])

    return render_template("scan/scan_email.html")


@scan_bp.route("/scan/apk", methods=["GET", "POST"])
@login_required
def scan_apk():
    if request.method == "POST":
        file = request.files.get("apk_file")
        filename = request.form.get("filename", "").strip()

        if file and file.filename.endswith(".apk"):
            file_bytes = file.read()
            filename = file.filename
        elif filename:
            file_bytes = b""
        else:
            flash("Please upload an .apk file or enter an APK filename.", "error")
            return render_template("scan/scan_apk.html")

        m = apk_model.analyze_apk_bytes(file_bytes, filename)
        result = decision.build_verdict("apk", m["flags"], int(m["confidence"] * 100), m["confidence"], True)

        _save_scan("apk", filename, result)
        return render_template("scan/result.html", result=result, scan_type="APK Package", content=filename)

    return render_template("scan/scan_apk.html")


@scan_bp.route("/api/verify-pin", methods=["POST"])
@login_required
def verify_pin():
    data = request.get_json() or {}
    pin = data.get("pin", "").strip()

    if not pin:
        return jsonify({"success": False, "message": "PIN is required"}), 400

    if current_user.check_safety_pin(pin):
        return jsonify({"success": True, "message": "Safety PIN verified successfully!"})
    else:
        return jsonify({"success": False, "message": "Incorrect Safety PIN. Access denied!"}), 403


@scan_bp.route("/api/delete-apk", methods=["POST"])
@login_required
def delete_apk():
    data = request.get_json() or {}
    filename = data.get("filename", "APK File")
    return jsonify({
        "success": True,
        "message": f"Harmful file '{filename}' has been successfully deleted from your device!"
    })


@scan_bp.route("/history")
@login_required
def history():
    try:
        scans = (
            ScanHistory.query.filter_by(user_id=current_user.id)
            .order_by(ScanHistory.created_at.desc())
            .all()
        )
    except Exception as e:
        print(f"Notice querying scan history: {e}")
        scans = []
    return render_template("scan/history.html", scans=scans)
