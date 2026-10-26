import pytest
import app as api


@pytest.fixture
def client(tmp_path, monkeypatch):
    db_path = tmp_path / "test_records.db"
    monkeypatch.setattr(api, "DB_PATH", db_path)
    api.init_db()

    api.app.config["TESTING"] = True

    with api.app.test_client() as client:
        yield client


def register(client, username, password="StrongPass123!"):
    return client.post(
        "/register",
        json={"username": username, "password": password},
    )


def login(client, username, password="StrongPass123!"):
    response = client.post(
        "/login",
        json={"username": username, "password": password},
    )
    if response.status_code == 200:
        return {"Authorization": "Bearer " + response.json["access_token"]}
    return None


def test_registration_and_login(client):
    response = register(client, "alice")
    assert response.status_code == 201

    headers = login(client, "alice")
    assert headers is not None


def test_registration_cannot_assign_admin(client):
    response = client.post(
        "/register",
        json={
            "username": "alice",
            "password": "StrongPass123!",
            "role": "admin",
        },
    )
    assert response.status_code == 400


def test_record_requires_authentication(client):
    response = client.post(
        "/records",
        json={"title": "Test", "body": "Private content"},
    )
    assert response.status_code == 401


def test_user_cannot_read_another_users_record(client):
    assert register(client, "alice").status_code == 201
    assert register(client, "bobby").status_code == 201

    alice_headers = login(client, "alice")
    bobby_headers = login(client, "bobby")

    created = client.post(
        "/records",
        json={"title": "Alice's record", "body": "Private"},
        headers=alice_headers,
    )
    assert created.status_code == 201
    record_id = created.json["id"]

    response = client.get(
        f"/records/{record_id}",
        headers=bobby_headers,
    )
    assert response.status_code in (403, 404)


def test_sql_like_title_is_stored_as_text(client):
    assert register(client, "alice").status_code == 201
    headers = login(client, "alice")

    title = "' OR '1'='1"
    created = client.post(
        "/records",
        json={"title": title, "body": "Harmless test"},
        headers=headers,
    )
    assert created.status_code == 201

    response = client.get(
        f"/records/{created.json['id']}",
        headers=headers,
    )
    assert response.status_code == 200
    assert response.json["title"] == title