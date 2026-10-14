# Secure Authentication Lab — Security Note

## 1. Objective
This project demonstrates secure user authentication using Python and Flask.

## 2. Security Measures
- **Password security:** Passwords are hashed using Werkzeug before storage.
- **Input validation:** Registration and login inputs are checked by the application.
- **Rate limiting:** Repeated login attempts are limited using Flask-Limiter.
- **CSRF protection:** Flask-WTF protects form submissions against cross-site request forgery.
- **Session security:** The application uses session management and secure cookie settings.
- **Access control:** Only authenticated users can access the dashboard.
- **Logout:** Users can log out through a POST request.

## 3. Testing
The automated test suite completed with 7 passed tests. The tests cover registration, password hashing, successful and unsuccessful login, dashboard access control, logout, and CSRF protection.

## 4. Known Limitation
The local development setup uses in-memory rate-limit storage. This is suitable for a learning lab but is not recommended for production. A production deployment should use persistent rate-limit storage, HTTPS, and securely managed environment variables.

## 5. Purpose
This is an educational project intended to demonstrate basic authentication security controls. It has not been independently audited and should not be considered production-ready.
