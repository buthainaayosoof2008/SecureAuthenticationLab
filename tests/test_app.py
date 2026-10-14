
import os

os.environ.setdefault(
    "APP_SECRET_KEY",
    "test-only-secret-key-do-not-use-in-production"
)

import pytest
import app as auth_app


@pytest.fixture
def client(tmp_path, monkeypatch):
    # Create a separate database for each test.
    test_database = tmp_path / "test_users.db"
    monkeypatch.setattr(auth_app, "DATABASE", test_database)

    auth_app.initialize_database()

    auth_app.app.config.update(
        TESTING=True,
        WTF_CSRF_ENABLED=False
    )

    with auth_app.app.test_client() as test_client:
        # Use a different IP for each test so rate-limit counters
        # from one test cannot affect another test.
        unique_number = abs(hash(str(test_database))) % 254 + 1
        test_client.environ_base["REMOTE_ADDR"] = (
            f"10.0.0.{unique_number}"
        )

        yield test_client


def register_user(client):
    return client.post(
        "/register",
        data={
            "username": "test_user",
            "password": "StrongTestPassword123!"
        },
        follow_redirects=True
    )


def test_registration_succeeds(client):
    response = register_user(client)

    assert response.status_code == 200
    assert b"Account created successfully" in response.data


def test_password_is_not_stored_as_plain_text(client):
    register_user(client)

    user = auth_app.get_user("test_user")

    assert user is not None
    assert user["password_hash"] != "StrongTestPassword123!"
    assert user["password_hash"].startswith("scrypt:")


def test_valid_login_opens_dashboard(client):
    register_user(client)

    response = client.post(
        "/login",
        data={
            "username": "test_user",
            "password": "StrongTestPassword123!"
        },
        follow_redirects=True
    )

    assert response.status_code == 200
    assert b"Welcome, test_user!" in response.data


def test_invalid_password_is_rejected(client):
    register_user(client)

    response = client.post(
        "/login",
        data={
            "username": "test_user",
            "password": "WrongPassword123!"
        },
        follow_redirects=True
    )

    assert response.status_code == 200
    assert b"Invalid username or password." in response.data
    assert b"Welcome, test_user!" not in response.data


def test_dashboard_requires_login(client):
    response = client.get("/dashboard")

    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_logout_removes_access(client):
    register_user(client)

    client.post(
        "/login",
        data={
            "username": "test_user",
            "password": "StrongTestPassword123!"
        }
    )

    client.post("/logout")

    response = client.get("/dashboard")

    assert response.status_code == 302
    assert "/login" in response.headers["Location"]

def test_csrf_rejects_post_without_token(client):
    import app as auth_app

    auth_app.app.config["WTF_CSRF_ENABLED"] = True

    response = client.post(
        "/register",
        data={
            "username": "csrf_test_user",
            "password": "StrongTestPassword123!"
        }
    )

    assert response.status_code == 400
