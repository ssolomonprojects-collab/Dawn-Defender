

        AI-Powered Spam & Phishing Detection System
A Machine Learning-based Web Application for Detecting Spam Messages, Phishing URLs and Emails in Real Time


?? Project Overview
This project is an AI-powered cybersecurity web application that helps users identify Spam SMS messages and Phishing URLs/Emails using Machine Learning models. The system analyses user-provided SMS text or website URLs and instantly predicts whether they are Safe or Malicious, helping users avoid scams, phishing attacks, and fraudulent messages.

?? Team Details
Team Name: Golden Dawn
Name
    Role
Srirangarajan U
Machine Learning 
Solomon S
Frontend Development
Kalaicharan S (Leader)
Backend Development
Jeyanthan S
Documentation & Testing


Hackathon/Event: Rush Hour 24
Institution: Sathyabama University
?? Problem Statement
The rapid growth of digital communication has significantly increased the risk of cyber threats such as spam messages, spam emails, and phishing websites. There is a need for a unified, intelligent, and user-friendly solution that can accurately detect multiple forms of online threats in real time and help users make safer decisions while using digital communication platforms.

?? Proposed Solution
Our project presents an AI-Powered Spam SMS, Spam Email, and Phishing URL Detection System, a web-based cybersecurity application that uses Machine Learning to identify malicious digital content in real time.
The application enables users to:
* Analyse SMS messages and classify them as Spam or Legitimate.
* Analyse email content and classify it as Spam or Legitimate.
* Analyse website URLs and classify them as Phishing or Safe.
Each module is powered by a dedicated Machine Learning model trained on relevant datasets to ensure accurate and efficient predictions. The models are integrated into a Flask-based web application with a simple and intuitive interface, allowing users to receive instant results without requiring technical expertise.
By combining multiple threat detection capabilities into a single platform, the system enhances user awareness, improves online safety, and contributes to protecting individuals from common cyber threats such as phishing attacks, spam campaigns, and online fraud.

? Features
?? Multi-Threat Detection
*     Detects Spam SMS, Spam Emails, and Phishing URLs within a single web application.
* Eliminates the need for multiple cybersecurity tools.
?? AI-Powered Prediction
* Uses trained Machine Learning models to accurately classify user inputs.
* Provides fast and reliable predictions based on learned patterns from real-world datasets.
?? Spam SMS Detection
* Analyses SMS messages and classifies them as Spam or Legitimate.
?? Spam Email Detection
* Examines email content and predicts whether it is Spam or Legitimate.
?? Phishing URL Detection
* Evaluates website URLs to determine whether they are Safe or Phishing.
??? User-Friendly Web Interface
* Clean and responsive interface built using HTML, CSS, and JavaScript.
* Easy to use without requiring technical knowledge.
?? Modular Architecture
* Frontend, backend, and AI models are organised into separate modules, making the project scalable and easy to maintain.
?? Easy Scalability
* Designed to support future enhancements such as QR code phishing detection, malicious file analysis, multilingual spam detection, and browser extension integration.


??? Complete Tech Stack
Our project combines modern web technologies with Machine Learning to provide an intelligent cybersecurity solution for detecting Spam SMS, Spam Emails, and Phishing URLs.
Frontend
HTML5
Structure and layout of web pages
CSS3
Styling, animations, and responsive design
JavaScript (ES6)
Client-side interactivity and form validation


Backend
Python 3.x
Core programming language
Flask
Web framework for handling routes, requests, and model integration


Machine Learning
Scikit-learn
Training and deploying Machine Learning models
Pandas
Data preprocessing and dataset manipulation
NumPy
Numerical computations and array operations
Joblib / Pickle
Saving and loading trained ML models


AI Models
Spam SMS Detection Model
Trained using Google Colab
Spam Email Detection Model
Trained using Google Colab
Phishing URL Detection Model
Trained using Google Colab

Datasets
Spam SMS Dataset
Downloaded from Kaggle
Spam Email Dataset
Downloaded from Kaggle
Phishing URL Dataset
Downloaded from Kaggle

Development Environment
Visual Studio Code
Source code editor
Google Colab
Model training and experimentation
Git
Version control
GitHub
Source code hosting and collaboration
??? System Architecture Diagram

?? Detailed Workflow
The AI-Powered Spam SMS, Spam Email, and Phishing URL Detection System follows a structured workflow to analyse user input and provide accurate predictions in real time. The workflow consists of data collection, model training, user interaction, input processing, prediction, and result generation.

1. Dataset Collection
The project begins with collecting publicly available datasets for training the Machine Learning models.
* Spam SMS Dataset – Contains labelled SMS messages classified as Spam or Legitimate.
* Spam Email Dataset – Contains labelled email messages classified as Spam or Legitimate.
* Phishing URL Dataset – Contains labelled URLs classified as Phishing or Safe.
These datasets serve as the foundation for training the AI models.

2. Data Preprocessing
Before training, the datasets undergo preprocessing to improve data quality and model performance.
For SMS and Email
* Remove unnecessary characters and symbols.
* Convert text to lowercase.
* Remove punctuation and extra spaces.
* Tokenise the text into individual words.
* Convert textual data into numerical feature vectors.
For URLs
* Validate the URL format.
* Extract meaningful URL features such as length, special characters, domain characteristics, and other relevant indicators.
* Convert extracted features into a numerical format suitable for Machine Learning.

3. Model Training
Separate Machine Learning models are trained for each detection module.
* Spam SMS Detection Model
* Spam Email Detection Model
* Phishing URL Detection Model
Each model learns patterns from its respective dataset and is evaluated using appropriate performance metrics. After successful training, the models are saved as .pkl files for deployment.

4. Model Integration
The trained models are integrated into a Flask-based web application.
During application startup:
* All trained models are loaded into memory.
* Label encoders (where applicable) are loaded.
* Feature extraction modules are initialised.
* The application becomes ready to process user requests.

5. User Interaction
The user accesses the application through a web browser.
The home page provides three detection modules:
* ?? Spam SMS Detection
* ?? Spam Email Detection
* ?? Phishing URL Detection
The user selects the required module and enters the corresponding input.

6. Input Validation
Before prediction, the application validates user input by:
* Checking for empty input fields.
* Removing unnecessary whitespace.
* Verifying that the input is in the expected format.
* Preventing invalid or malformed submissions.
This ensures reliable predictions and enhances application stability.

7. AI-Based Prediction
Depending on the selected module, the application performs the following:
Spam SMS Detection
* The SMS text is pre-processed.
* The processed text is converted into feature vectors.
* The Spam SMS model predicts whether the message is Spam or Legitimate.
Spam Email Detection
* The email content is cleaned and pre-processed.
* The processed content is transformed into feature vectors.
* The Spam Email model predicts whether the email is Spam or Legitimate.
Phishing URL Detection
* The entered URL is processed using the feature extraction module.
* Relevant URL characteristics are generated.
* The Phishing URL model predicts whether the URL is Safe or Phishing.

8. Result Generation
After prediction, the system generates a clear and user-friendly result.
The application displays:
* Prediction status
* Detection category
* Classification result
Examples:
* ? Legitimate SMS
* ? Spam SMS
* ? Legitimate Email
* ? Spam Email
* ? Safe URL
* ? Phishing URL

Folder Structure
?? sentinel-ai-web
??? ?? run.py
??? ?? requirements.txt
??? ?? README.md
??? ?? .gitignore
?
??? ?? android
?   ??? ?? app
?       ??? ?? src
?           ??? ?? main
?               ??? ?? AndroidManifest.xml
?               ??? ?? java
?                   ??? ?? com
?                       ??? ?? dawndefender
?                           ??? ?? app
?                               ??? ?? DownloadWatcherService.kt
?                               ??? ?? ApkInspector.kt
?                               ??? ?? ApkActivity.kt
?                               ??? ?? PinGateActivity.kt
?
??? ?? instance
?   ??? ??? dawn_defender.db
?
??? ?? app
    ??? ?? __init__.py
    ??? ?? models.py
    ?
    ??? ?? auth
    ?   ??? ?? routes.py
    ?
    ??? ?? main
    ?   ??? ?? routes.py
    ?
    ??? ?? scan
    ?   ??? ?? routes.py
    ?
    ??? ?? ml
    ?   ??? ?? heuristics.py
    ?   ??? ?? decision.py
    ?   ??? ?? url_model.py
    ?   ??? ?? sms_model.py
    ?   ??? ?? email_model.py
    ?   ??? ?? apk_model.py
    ?   ??? ?? qr_model.py
    ?   ??? ?? trained_models
    ?       ??? ?? email_model.pkl
    ?       ??? ?? email_vectorizer.pkl
    ?       ??? ?? sms_model.pkl
    ?       ??? ?? sms_vectorizer.pkl
    ?       ??? ?? url_model.pkl
    ?
    ??? ?? static
    ?   ??? ?? css
    ?   ?   ??? ?? style.css
    ?   ??? ?? js
    ?   ?   ??? ?? app.js
    ?   ??? ?? manifest.json
    ?   ??? ?? sw.js
    ?
    ??? ?? templates
        ??? ?? base.html
        ??? ?? index.html
        ??? ?? auth
        ?   ??? ?? login.html
        ?   ??? ?? register.html
        ??? ?? main
        ?   ??? ?? dashboard.html
        ??? ?? scan
            ??? ?? scan_url.html
            ??? ?? scan_sms.html
            ??? ?? scan_email.html
            ??? ?? scan_apk.html
            ??? ?? result.html
            ??? ?? history.html

?? Installation
Simply open the live web application using the link below in any modern web browser:
?? Live Application: https://dawn-defender-tau.vercel.app/
Supported Browsers:
* Google Chrome
* Microsoft Edge
* Mozilla Firefox
* Safari
The application is hosted on Vercel with Supabase as the backend database, allowing users to access all features directly without downloading or installing any software.

?? Usage Guide
Step 1: Open the Application
Visit the live application using the link:
https://dawn-defender-tau.vercel.app/
Step 2: Register or Log In
Create a new account or log in with your existing credentials.
Step 3: Choose a Detection Module
Select the type of scan you want to perform:
* ?? Spam SMS Detection
* ?? Spam Email Detection
* ?? Phishing URL Detection
* ?? APK Malware Detection (if available)
Step 4: Enter the Required Input
Provide the SMS message, email content, URL, or APK file, depending on the selected module.
Step 5: Start the Scan
Click the Scan button to analyse the input using the integrated AI model.
Step 6: View the Results
The application instantly displays the analysis result, indicating whether the input is Safe/Legitimate or Spam/Phishing/Malicious.


?? Challenges Faced
During the development of Dawn Defender, our team encountered several technical and implementation challenges:
* Dataset Collection and Quality: Obtaining reliable and well-labelled datasets for Spam SMS, Spam Email, Phishing URLs, and APK analysis while ensuring sufficient data quality for model training.
* Data Preprocessing: Cleaning, transforming, and preparing different types of data (text, URLs, and APK metadata) required separate preprocessing techniques for each detection module.
* Model Selection and Optimisation: Choosing suitable Machine Learning algorithms and tuning them to achieve high prediction accuracy while maintaining low response times.
* Integration of Multiple AI Models: Combining multiple detection models into a single Flask application while ensuring smooth communication between the frontend, backend, and AI modules.
* Deployment and Database Integration: Configuring the application for deployment on Vercel and integrating Supabase for authentication and data management.
* User Experience: Designing a responsive and intuitive interface that allows users to perform scans easily while displaying results in a clear and understandable manner.

?? Future Scope
The project can be further enhanced with additional cybersecurity features and AI capabilities, including:
* Real-Time Threat Intelligence: Integrate live phishing and malware databases to improve detection of newly emerging threats.
* Advanced Deep Learning Models: Replace or complement traditional Machine Learning models with Transformer-based NLP models to improve spam detection accuracy.
* Browser Extension: Develop Chrome and Edge extensions to analyse websites automatically while users browse the internet.
* Mobile Application: Launch dedicated Android and iOS applications for on-the-go cybersecurity protection.
* Multilingual Detection: Support spam and phishing detection in multiple regional and international languages.
* Cloud-Based Model Updates: Enable automatic model retraining and deployment using newly collected datasets to continuously improve prediction performance.
* Threat Analytics Dashboard: Provide users with detailed scan history, threat statistics, and visual analytics for better cybersecurity awareness.
* Expanded Threat Detection: Extend the platform to detect QR code phishing, malicious attachments, fake websites, social engineering attempts, and other emerging cyber threats.








