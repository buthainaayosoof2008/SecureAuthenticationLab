# Secure Authentication Lab

## Project Overview
Secure Authentication Lab is a Python Flask web application designed to demonstrate secure user registration, login, session management, and logout.

## Security Features
- Password hashing using Werkzeug
- User authentication and session management
- Login rate limiting
- CSRF protection for form submissions
- Protected dashboard for authenticated users
- SQLite database for user information
- Secure session cookie settings

## Technologies Used
- Python
- Flask
- SQLite
- Flask-Limiter
- Flask-WTF
- Werkzeug
- Pytest

## Testing
The project currently has **7 passing tests** covering registration, password hashing, login, dashboard access control, logout, and CSRF protection.

## Run Locally
1. Create and activate a Python virtual environment.
2. Install dependencies using `pip install -r requirements.txt`.
3. Configure the `APP_SECRET_KEY` environment variable.
4. Run the Flask application using `python app.py`.
5. Open the local address shown in the terminal.

## Disclaimer
This project is for educational purposes and security testing in a controlled environment. Additional hardening is required before production use.
