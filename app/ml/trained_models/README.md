# Trained models go here

Download your trained models from Colab and drop them in this folder:

- `url_model.pkl` (+ `url_vectorizer.pkl` if you used one)
- `sms_model.pkl` (+ `sms_vectorizer.pkl`)
- `email_model.pkl` (+ `email_vectorizer.pkl`)
- `qr_model.pkl` (only if training a visual tampering classifier)

Then uncomment the loading code in the matching file under `app/ml/`
(`url_model.py`, `sms_model.py`, `email_model.py`, `qr_model.py`).

Do not commit large model files to Git if they're over ~50MB - use Git LFS
or a download link instead, and note that in your README.
