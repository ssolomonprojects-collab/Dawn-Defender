# Dawn Defender — Web App

Flask web application: register/login, and four scanners (URL, SMS, email,
QR code). Tested end-to-end in this build — register → login → scan → see
result → check history all confirmed working before this was handed to you.

## Setup

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
python run.py
```

Open http://localhost:5000 — the database (SQLite) is created automatically
on first run, no manual setup needed.

## How each feature works right now (before your models are plugged in)

Every scanner already works using rule-based heuristics alone:
- **URL**: checks HTTPS, suspicious domain extensions, lookalike/typosquatted
  brand names, raw IP addresses, excessive hyphens
- **SMS/Email**: checks for urgency language ("act now", "verify immediately"),
  embedded links
- **QR**: decodes the image (OpenCV, works with zero setup) and runs the
  decoded content through the same URL/text checks

This means the app is fully demo-able right now, today, with zero trained
models. Your Colab models make it smarter, not "make it work."

## Where to plug in your trained models

Each has its own file under `app/ml/`, with the exact spot marked:
- `app/ml/url_model.py`
- `app/ml/sms_model.py`
- `app/ml/email_model.py`
- `app/ml/qr_model.py` (only if you're training a visual tampering
  classifier — the decode step already works without one)

Drop your downloaded `.pkl` files into `app/ml/trained_models/`, then
uncomment the loading code in the matching file. Nothing else in the app
needs to change — `app/ml/decision.py` already knows how to combine a real
model's confidence score with the heuristic flags once `model_used` comes
back `True`.

## Folder structure

```
dawn-defender-web/
├── run.py
├── requirements.txt
├── instance/                  # SQLite DB lives here (auto-created)
└── app/
    ├── __init__.py            # app factory
    ├── models.py              # User, ScanHistory
    ├── auth/routes.py         # register, login, logout
    ├── main/routes.py         # landing page, dashboard
    ├── scan/routes.py         # the four scan pages + history
    ├── ml/
    │   ├── heuristics.py      # rule-based checks (works today)
    │   ├── decision.py        # combines heuristics + model into a verdict
    │   ├── url_model.py       # <- plug trained URL model in here
    │   ├── sms_model.py       # <- plug trained SMS model in here
    │   ├── email_model.py     # <- plug trained email model in here
    │   ├── qr_model.py        # QR decode (works today) + optional model
    │   └── trained_models/    # drop your .pkl files here
    ├── templates/             # one template per page
    └── static/css/style.css
```

## Notes

- Passwords are hashed (never stored in plaintext) via Werkzeug's
  `generate_password_hash`
- Registration only collects username, email, password — nothing else
- Uploaded QR images are deleted right after scanning, not kept on disk
- `SECRET_KEY` defaults to a dev value — set a real one via environment
  variable before deploying anywhere public:
  ```bash
  export SECRET_KEY="something-random-and-long"
  ```

