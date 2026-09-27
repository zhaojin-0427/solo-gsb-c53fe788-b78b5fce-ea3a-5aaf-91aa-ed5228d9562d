"""Integration fixtures: the API must be reachable with a live Postgres.

Run inside compose:  docker compose exec api pytest tests/ -q
"""
from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient

from app.main import app


def uniq(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


@pytest.fixture(scope="session")
def client():
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture()
def policy(client):
    """A fresh pure-DP policy (delta_total = 0) per test."""
    resp = client.post("/policies", json={
        "name": uniq("pol"),
        "epsilon_total": 5.0,
        "delta_total": 0.0,
        "per_subject_cap": 2,
        "dimensions": ["region", "age_band"],
    })
    assert resp.status_code == 201, resp.text
    return resp.json()


def upload(client, dataset_version: int, records: list[dict]):
    resp = client.post("/records", json={
        "dataset_version": dataset_version,
        "records": records,
    })
    assert resp.status_code == 201, resp.text
    return resp.json()


def seed_dataset(client, dataset_version: int | None = None):
    """3 subjects across 2 regions; alice exceeds the per-subject cap of 2.

    Uses a fresh dataset_version per call so repeated runs never collide with
    previously uploaded (immutable) record keys.
    """
    if dataset_version is None:
        dataset_version = uuid.uuid4().int % 1_000_000_000
    records = [
        {"record_key": "r1", "subject_id": "alice", "attributes": {"region": "us", "value": 5}},
        {"record_key": "r2", "subject_id": "alice", "attributes": {"region": "us", "value": 7}},
        {"record_key": "r3", "subject_id": "alice", "attributes": {"region": "us", "value": 100}},
        {"record_key": "r4", "subject_id": "bob", "attributes": {"region": "us", "value": 3}},
        {"record_key": "r5", "subject_id": "carol", "attributes": {"region": "eu", "value": 11}},
    ]
    upload(client, dataset_version, records)
    return dataset_version
