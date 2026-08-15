"""Isolated integrations and organization-access API.

It is intentionally a separate ASGI application: existing SecureFlow routes
continue operating unchanged until a deliberate deployment decision mounts
or proxies this service.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
from typing import Literal
from urllib.parse import urlencode

import httpx
from fastapi import Depends, FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

from integrations import store
from integrations import github
from integrations.permissions import require_role_permission
from integrations.security import current_user_id, decrypt_secret, encrypt_secret, generate_api_key

app = FastAPI(title="SecureFlow Integrations", version="1.0.0")

VALID_SCOPES = {"projects:read", "projects:write", "scans:read", "scans:run", "findings:read", "reports:read", "settings:manage", "integrations:manage"}


class OrganizationCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)


class MemberUpsert(BaseModel):
    user_id: str = Field(min_length=1, max_length=128)
    role: Literal["admin", "security", "viewer"]


class ApiKeyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    scopes: list[str] = ["scans:run", "findings:read"]


class RegistryConnect(BaseModel):
    provider: Literal["dockerhub", "ecr", "ghcr"]
    name: str = Field(min_length=1, max_length=100)
    credentials: dict[str, str]


class GitHubRepositorySelection(BaseModel):
    full_name: str = Field(min_length=3, max_length=300)


def _assert(organization_id: int, user_id: str, permission: str) -> None:
    require_role_permission(store.role_for(organization_id, user_id), permission)


@app.on_event("startup")
def startup() -> None:
    store.initialize()


@app.post("/organizations")
def create_organization(payload: OrganizationCreate, user_id: str = Depends(current_user_id)):
    return store.create_organization(payload.name.strip(), user_id)


@app.put("/organizations/{organization_id}/members")
def upsert_member(organization_id: int, payload: MemberUpsert, user_id: str = Depends(current_user_id)):
    _assert(organization_id, user_id, "members:manage")
    return store.add_member(organization_id, payload.user_id, payload.role)


@app.post("/organizations/{organization_id}/api-keys")
def create_key(organization_id: int, payload: ApiKeyCreate, user_id: str = Depends(current_user_id)):
    _assert(organization_id, user_id, "api_keys:manage")
    scopes = sorted(set(payload.scopes))
    invalid = set(scopes) - VALID_SCOPES
    if invalid or not scopes:
        raise HTTPException(status_code=400, detail="Key scopes must be non-empty supported scopes")
    raw, prefix, digest = generate_api_key()
    record = store.put_api_key(organization_id, payload.name.strip(), prefix, digest, scopes, user_id)
    return {**record, "key": raw}  # intentionally the only response containing the raw key


@app.get("/organizations/{organization_id}/api-keys")
def get_keys(organization_id: int, user_id: str = Depends(current_user_id)):
    _assert(organization_id, user_id, "api_keys:manage")
    return {"keys": store.list_api_keys(organization_id)}


@app.delete("/organizations/{organization_id}/api-keys/{key_id}")
def revoke_key(organization_id: int, key_id: int, user_id: str = Depends(current_user_id)):
    _assert(organization_id, user_id, "api_keys:manage")
    if not store.revoke_api_key(organization_id, key_id):
        raise HTTPException(status_code=404, detail="API key not found or already revoked")
    return {"revoked": True}


@app.post("/organizations/{organization_id}/registries")
def connect_registry(organization_id: int, payload: RegistryConnect, user_id: str = Depends(current_user_id)):
    _assert(organization_id, user_id, "integrations:manage")
    if not payload.credentials or any(not value for value in payload.credentials.values()):
        raise HTTPException(status_code=400, detail="Registry credentials are required")
    # Validation is provider-specific and does not retain plaintext beyond this request.
    return store.put_integration(organization_id, payload.provider, payload.name.strip(), encrypt_secret(str(payload.credentials)), {"credential_fields": sorted(payload.credentials)}, user_id)


@app.get("/organizations/{organization_id}/integrations")
def get_integrations(organization_id: int, user_id: str = Depends(current_user_id)):
    _assert(organization_id, user_id, "integrations:manage")
    return {"integrations": store.list_integrations(organization_id)}


@app.delete("/organizations/{organization_id}/integrations/{integration_id}")
def disconnect_integration(organization_id: int, integration_id: int, user_id: str = Depends(current_user_id)):
    _assert(organization_id, user_id, "integrations:manage")
    if not store.revoke_integration(organization_id, integration_id):
        raise HTTPException(status_code=404, detail="Integration not found or already revoked")
    return {"revoked": True}


@app.get("/github/authorize")
def github_authorize(organization_id: int = Query(...), user_id: str = Depends(current_user_id)):
    _assert(organization_id, user_id, "integrations:manage")
    client_id, redirect_uri = github.authorize_settings()
    state = secrets.token_urlsafe(32)
    store.put_github_oauth_state(hashlib.sha256(state.encode()).hexdigest(), organization_id, user_id)
    return {"authorize_url": "https://github.com/login/oauth/authorize?" + urlencode({"client_id": client_id, "redirect_uri": redirect_uri, "scope": "repo read:org", "state": state})}


@app.get("/github/callback")
def github_callback(code: str = Query(..., min_length=1), state: str = Query(..., min_length=1)):
    state_record = store.consume_github_oauth_state(hashlib.sha256(state.encode()).hexdigest())
    if not state_record:
        raise HTTPException(status_code=400, detail="Invalid, expired, or already-used OAuth state")
    token = github.exchange_code(code)
    account = github.authenticated_user(token["access_token"])
    credentials = {key: token[key] for key in ("access_token", "token_type", "scope") if token.get(key)}
    integration = store.put_integration(
        state_record["organization_id"],
        "github",
        account["login"],
        encrypt_secret(json.dumps(credentials)),
        {"github_account": account},
        state_record["user_id"],
    )
    return {"connected": True, "integration": integration}


def _github_token(organization_id: int, integration_id: int) -> tuple[dict, str]:
    integration = store.get_active_integration(organization_id, integration_id, "github")
    if not integration:
        raise HTTPException(status_code=404, detail="Active GitHub integration not found")
    try:
        credentials = json.loads(decrypt_secret(integration["encrypted_credentials"]))
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=500, detail="Stored GitHub credentials are invalid") from exc
    token = credentials.get("access_token")
    if not token:
        raise HTTPException(status_code=500, detail="Stored GitHub credentials are incomplete")
    return integration, token


@app.get("/organizations/{organization_id}/integrations/{integration_id}/github/repositories")
def github_repositories(
    organization_id: int,
    integration_id: int,
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=100, ge=1, le=100),
    user_id: str = Depends(current_user_id),
):
    _assert(organization_id, user_id, "integrations:manage")
    _, token = _github_token(organization_id, integration_id)
    return {"repositories": github.list_repositories(token, page, per_page), "page": page, "per_page": per_page}


@app.put("/organizations/{organization_id}/integrations/{integration_id}/github/repository")
def select_github_repository(
    organization_id: int,
    integration_id: int,
    payload: GitHubRepositorySelection,
    user_id: str = Depends(current_user_id),
):
    _assert(organization_id, user_id, "integrations:manage")
    integration, token = _github_token(organization_id, integration_id)
    repository = github.get_repository(token, payload.full_name)
    metadata = {**integration["metadata"], "selected_repository": repository}
    updated = store.update_integration_metadata(organization_id, integration_id, metadata)
    return {"integration": updated, "repository": repository}
