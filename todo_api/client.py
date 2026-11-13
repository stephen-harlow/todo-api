"""Bounded, credential-safe client for the native Vikunja v2 API.

Supported wire contract: official https://vikunja.io/docs/api-v2/ and read-only
https://try.vikunja.io/api/v2/openapi.json, v2.8.0-126-g5e0caf2b, inspected
2026-11-12. This pins the implemented subset, not a qualified deployment release.
Labels/relations are read-only Task fields: use their dedicated POST endpoints.
No request is automatically retried. Reconcile uncertain writes before replay.
PATCH is disabled by default: the isolated v2.8.0 canary ignored stale If-Match.
Enable conditional_patch_verified only after testing the selected server release.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from http.client import HTTPException
import html
import json
import math
import os
import re
import stat
from typing import Any, Callable, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


class TodoAPIError(RuntimeError):
    """Sanitized API/configuration failure; response bodies never enter errors."""

    def __init__(self, message: str, *, status: int | None = None):
        super().__init__(message)
        self.status = status


class TodoConflictError(TodoAPIError):
    """The server rejected an update; fetch and review before changing intent."""


class TodoWriteUncertainError(TodoAPIError):
    """A write may have applied. Reconcile with server state before any replay."""


def _secret(value: str) -> bool:
    return (
        isinstance(value, str)
        and 0 < len(value) <= 8192
        and all(33 <= ord(c) <= 126 for c in value)
    )


def _env_secret(env: Mapping[str, str], name: str) -> str | None:
    direct, path = env.get(name), env.get(name + "_FILE")
    if direct is not None and path is not None:
        raise TodoAPIError(f"Configure only {name} or {name}_FILE.")
    if path is None:
        return direct
    try:
        # Inspect the opened descriptor: reject symlinks, FIFO/devices and unsafe modes.
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "r", encoding="utf-8") as stream:
            info = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_mode & 0o077
                or info.st_uid not in (0, os.getuid())
                or info.st_size > 8192
            ):
                raise TodoAPIError("Secret file must be restricted, owned and regular.")
            value = stream.read(8193)
            if len(value) > 8192:
                raise TodoAPIError("Secret file exceeds the size limit.")
            return value.rstrip("\r\n")
    except (OSError, UnicodeError, ValueError):
        raise TodoAPIError("Unable to read a restricted secret file.") from None


@dataclass(frozen=True)
class TodoAPIConfig:
    """HTTPS endpoint and bot credentials; secrets are excluded from repr.

    Environment: TODO_API_URL, TODO_API_TOKEN[_FILE], optional paired
    TODO_CF_ACCESS_CLIENT_ID[_FILE] and TODO_CF_ACCESS_CLIENT_SECRET[_FILE].
    Files must be owner/root-owned regular files with no group/other permissions.
    HTTP is only allowed for an explicitly opted-in local canary.
    """

    base_url: str
    token: str = field(repr=False)
    cf_client_id: str | None = field(default=None, repr=False)
    cf_client_secret: str | None = field(default=None, repr=False)
    timeout: float = 15.0
    max_response_bytes: int = 2_000_000
    per_page: int = 100
    max_pages: int = 100
    max_items: int = 10_000
    allow_insecure_localhost: bool = False
    conditional_patch_verified: bool = False

    def __post_init__(self):
        try:
            parsed = urlsplit(self.base_url)
            valid = (
                bool(parsed.hostname)
                and parsed.username is None
                and parsed.password is None
                and not parsed.query
                and not parsed.fragment
                and parsed.port != 0
                and parsed.path in ("", "/", "/api/v2", "/api/v2/")
                and not any(ord(c) <= 32 or ord(c) >= 127 for c in self.base_url)
            )
            local = (
                self.allow_insecure_localhost is True
                and parsed.scheme == "http"
                and parsed.hostname in ("localhost", "127.0.0.1", "::1")
            )
            if not valid or not (parsed.scheme == "https" or local):
                raise ValueError
        except (ValueError, TypeError, AttributeError):
            raise TodoAPIError(
                "Configure a valid HTTPS instance URL or /api/v2 base."
            ) from None
        object.__setattr__(
            self,
            "base_url",
            self.base_url.rstrip("/")
            + ("" if parsed.path.rstrip("/") == "/api/v2" else "/api/v2"),
        )
        if not _secret(self.token):
            raise TodoAPIError("A valid Vikunja bot API token is required.")
        if (self.cf_client_id is None) != (self.cf_client_secret is None) or (
            self.cf_client_id is not None
            and not (_secret(self.cf_client_id) and _secret(self.cf_client_secret))
        ):
            raise TodoAPIError("Cloudflare service credentials must be a valid pair.")
        if (
            isinstance(self.timeout, bool)
            or not isinstance(self.timeout, (int, float))
            or not math.isfinite(self.timeout)
            or not 0 < self.timeout <= 120
        ):
            raise TodoAPIError("API timeout must be positive and at most 120 seconds.")
        for name, maximum in [
            ("max_response_bytes", 10_000_000),
            ("per_page", 1000),
            ("max_pages", 1000),
            ("max_items", 100_000),
        ]:
            value = getattr(self, name)
            if type(value) is not int or not 0 < value <= maximum:
                raise TodoAPIError("API limits must be bounded positive integers.")

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> TodoAPIConfig:
        """Read configuration without printing credentials or their file paths."""
        env = os.environ if env is None else env
        return cls(
            env.get("TODO_API_URL", ""),
            _env_secret(env, "TODO_API_TOKEN"),
            _env_secret(env, "TODO_CF_ACCESS_CLIENT_ID"),
            _env_secret(env, "TODO_CF_ACCESS_CLIENT_SECRET"),
        )


@dataclass(frozen=True)
class TaskResult:
    """Task snapshot and exact strong ETag required for a later update."""

    task: dict[str, Any]
    etag: str


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Even same-origin redirects are refused: Access login must never succeed.
        return None


def _id(value: int) -> int:
    if type(value) is not int or not 0 < value < 2**63:
        raise TodoAPIError("Resource IDs must be positive integers.")
    return value


def _etag(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(
        r'"[\x21\x23-\x7e]{1,256}"', value
    ):
        raise TodoAPIError("An exact strong ETag from get_task is required.")
    return value


_TASK_FIELDS = {
    "title": str,
    "description": str,
    "done": bool,
    "priority": int,
    "due_date": str,
    "start_date": str,
    "end_date": str,
    "repeat_after": int,
    "repeat_mode": int,
}
_RELATIONS = {
    "subtask",
    "parenttask",
    "related",
    "duplicateof",
    "duplicates",
    "blocking",
    "blocked",
    "precedes",
    "follows",
    "copiedfrom",
    "copiedto",
}


def _task_fields(changes: dict[str, Any]) -> None:
    if not isinstance(changes, dict) or not changes:
        raise TodoAPIError("Provide supported task fields to change.")
    for name, value in changes.items():
        if name not in _TASK_FIELDS or type(value) is not _TASK_FIELDS[name]:
            raise TodoAPIError("Unsupported task field or value type.")
        if isinstance(value, str) and len(value) > 500_000:
            raise TodoAPIError("Task field exceeds the size limit.")
    if "title" in changes and not changes["title"].strip():
        raise TodoAPIError("Task title must not be empty.")
    if "priority" in changes and not 0 <= changes["priority"] <= 5:
        raise TodoAPIError("Task priority must be between zero and five.")
    if "repeat_mode" in changes and changes["repeat_mode"] not in (0, 1, 2):
        raise TodoAPIError("Unsupported repeat mode.")
    if "repeat_after" in changes and not 0 <= changes["repeat_after"] < 2**63:
        raise TodoAPIError("Repeat interval must be a nonnegative integer.")


class VikunjaClient:
    """Native v2 subset. Inject transport(request, timeout=seconds) for local tests."""

    def __init__(self, config: TodoAPIConfig, *, transport: Callable | None = None):
        self.config = config
        self._transport = transport or build_opener(_NoRedirect()).open

    def _request(
        self, method: str, path: str, *, body=None, etag=None, query=None
    ) -> tuple[dict[str, Any], dict[str, str]]:
        write = method != "GET"
        headers = {
            "Authorization": f"Bearer {self.config.token}",
            "Accept": "application/json",
            "User-Agent": "todo-api/0.1.0",
        }
        if self.config.cf_client_id is not None:
            headers["CF-Access-Client-Id"] = self.config.cf_client_id
            headers["CF-Access-Client-Secret"] = self.config.cf_client_secret
        if etag is not None:
            headers["If-Match"] = _etag(etag)
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body, allow_nan=False).encode("utf-8")
        url = self.config.base_url + path + ("?" + urlencode(query) if query else "")
        request = Request(url, data=data, headers=headers, method=method)
        try:
            with self._transport(request, timeout=self.config.timeout) as response:
                self._check_status(response.status, method)
                response_headers = {k.lower(): v for k, v in response.headers.items()}
                if (
                    response_headers.get("content-type", "").split(";")[0].lower()
                    != "application/json"
                ):
                    raise TodoAPIError(
                        "API returned a non-JSON response; check Access service authorization."
                    )
                raw = response.read(self.config.max_response_bytes + 1)
                if len(raw) > self.config.max_response_bytes:
                    raise TodoAPIError(
                        "API response exceeds the configured size limit."
                    )
                result = json.loads(raw)
                if not isinstance(result, dict):
                    raise TodoAPIError("API returned an invalid JSON resource.")
                return result, response_headers
        except HTTPError as error:
            try:
                try:
                    self._check_status(error.code, method)
                except TodoAPIError as sanitized:
                    raise sanitized from None
            finally:
                error.close()
            raise TodoAPIError("API request failed.") from None
        except TodoWriteUncertainError:
            raise
        except TodoConflictError:
            raise
        except TodoAPIError as error:
            if write and error.status is None:
                raise TodoWriteUncertainError(
                    "Write outcome unknown; reconcile server state before replay."
                ) from None
            raise
        except (OSError, URLError, HTTPException, ValueError, RecursionError):
            kind = TodoWriteUncertainError if write else TodoAPIError
            raise kind(
                "Write outcome unknown; reconcile server state before replay."
                if write
                else "API request failed or returned invalid JSON."
            ) from None

    @staticmethod
    def _check_status(status: int, method: str) -> None:
        if status == (201 if method == "POST" else 200):
            return
        kind = TodoConflictError if status in (409, 412) else TodoAPIError
        if method != "GET" and (status >= 500 or 200 <= status < 300):
            raise TodoWriteUncertainError(
                "Write outcome unknown; reconcile server state before replay.",
                status=status,
            )
        raise kind(f"Vikunja API request refused (HTTP {status}).", status=status)

    @staticmethod
    def _resource(value: Any, *, write=False) -> dict[str, Any]:
        valid = (
            isinstance(value, dict)
            and type(value.get("id")) is int
            and 0 < value["id"] < 2**63
            and isinstance(value.get("title"), str)
            and bool(value["title"].strip())
        )
        if not valid:
            kind = TodoWriteUncertainError if write else TodoAPIError
            raise kind(
                "API returned an invalid resource; reconcile any write before replay."
            )
        return value

    def _task(
        self, value: Any, *, project_id=None, task_id=None, write=False
    ) -> dict[str, Any]:
        value = self._resource(value, write=write)
        valid = (
            type(value.get("project_id")) is int
            and value["project_id"] > 0
            and (project_id is None or value["project_id"] == project_id)
            and (task_id is None or value["id"] == task_id)
            and ("done" not in value or type(value["done"]) is bool)
        )
        labels = value.get("labels")
        if labels is not None:
            valid = valid and isinstance(labels, list)
            if valid:
                for label in labels:
                    self._resource(label, write=write)
        if not valid:
            kind = TodoWriteUncertainError if write else TodoAPIError
            raise kind("API returned an invalid or out-of-scope task.")
        return value

    def _comment(self, value: Any, *, write=False) -> dict[str, Any]:
        valid = (
            isinstance(value, dict)
            and type(value.get("id")) is int
            and 0 < value["id"] < 2**63
            and isinstance(value.get("comment"), str)
            and "title" not in value
        )
        if not valid:
            kind = TodoWriteUncertainError if write else TodoAPIError
            raise kind("API returned an invalid comment resource.")
        return value

    def _list(self, path: str, *, project_id=None, parser=None) -> list[dict[str, Any]]:
        items, seen, expected_total, expected_pages = [], set(), None, None
        for number in range(1, self.config.max_pages + 1):
            data, _ = self._request(
                "GET", path, query={"page": number, "per_page": self.config.per_page}
            )
            if (
                any(
                    type(data.get(key)) is not int
                    for key in ["page", "total", "per_page", "total_pages"]
                )
                or data["page"] != number
                or not 0 < data["per_page"] <= self.config.per_page
                or not 0 <= data["total"] <= self.config.max_items
                or not 0 <= data["total_pages"] <= self.config.max_pages
            ):
                raise TodoAPIError("Invalid or excessive API pagination.")
            total, pages = data["total"], data["total_pages"]
            if number == 1:
                expected_total, expected_pages = total, pages
            if (
                total != expected_total
                or pages != expected_pages
                or (pages == 0 and total != 0)
                or (total == 0 and pages > 1)
            ):
                raise TodoAPIError("API pagination changed; retry the read explicitly.")
            batch = data.get("items")
            if batch is None and total == 0:
                batch = []  # Native Go nil slices encode as null on empty results.
            if not isinstance(batch, list) or len(batch) > data["per_page"]:
                raise TodoAPIError("Invalid API page items.")
            for item in batch:
                parsed = (
                    parser(item)
                    if parser is not None
                    else self._task(item, project_id=project_id)
                    if project_id
                    else self._resource(item)
                )
                if parsed["id"] in seen:
                    raise TodoAPIError(
                        "Duplicate resource in API pagination; retry the read explicitly."
                    )
                seen.add(parsed["id"])
                items.append(parsed)
            if len(items) > total or (not batch and number < pages):
                raise TodoAPIError("Incomplete or inconsistent API pagination.")
            if number >= pages:
                if len(items) != total:
                    raise TodoAPIError("API pagination did not return every resource.")
                return items
        raise TodoAPIError("API pagination exceeds the configured limit.")

    def list_tasks(self, project_id: int) -> list[dict[str, Any]]:
        """Read every task in exactly one project; fail rather than return partial data."""
        return self._list(f"/projects/{_id(project_id)}/tasks", project_id=project_id)

    def list_projects(self) -> list[dict[str, Any]]:
        """Read every project visible to this bot; fail rather than return partial data."""
        return self._list("/projects")

    def create_project(
        self, title: str, description: str = "", identifier: str = ""
    ) -> dict[str, Any]:
        """Create a project once; the caller must durably record intent and reconcile."""
        if not isinstance(title, str) or not title.strip() or len(title) > 250:
            raise TodoAPIError("Project title must contain one to 250 characters.")
        if not isinstance(description, str) or len(description) > 500_000:
            raise TodoAPIError("Project description exceeds the size limit.")
        if not isinstance(identifier, str) or len(identifier) > 10:
            raise TodoAPIError("Project identifier must be at most 10 characters.")
        body: dict[str, Any] = {"title": title, "description": description}
        if identifier:
            body["identifier"] = identifier
        data, _ = self._request("POST", "/projects", body=body)
        return self._resource(data, write=True)

    def get_task(self, task_id: int) -> TaskResult:
        """Read a task snapshot with the exact ETag needed for conditional PATCH."""
        task_id = _id(task_id)
        data, headers = self._request("GET", f"/tasks/{task_id}")
        data = self._task(data, task_id=task_id)
        if type(data.get("max_permission")) is not int or data[
            "max_permission"
        ] not in (0, 1, 2):
            raise TodoAPIError("API omitted a valid task permission level.")
        return TaskResult(data, _etag(headers.get("etag", "")))

    def create_task(
        self,
        project_id: int,
        title: str,
        description: str = "",
        priority: int = 0,
        **fields,
    ) -> dict[str, Any]:
        """Create once. The caller must durably record intent and reconcile uncertainty."""
        project_id = _id(project_id)
        body = {
            "title": title,
            "description": description,
            "priority": priority,
            **fields,
        }
        _task_fields(body)
        data, _ = self._request("POST", f"/projects/{project_id}/tasks", body=body)
        return self._task(data, project_id=project_id, write=True)

    def update_task(
        self, task_id: int, changes: dict[str, Any], etag: str
    ) -> dict[str, Any]:
        """PATCH explicit fields only on a server verified to enforce If-Match."""
        if self.config.conditional_patch_verified is not True:
            raise TodoAPIError(
                "Task updates require verified server If-Match enforcement."
            )
        task_id = _id(task_id)
        _task_fields(changes)
        data, _ = self._request("PATCH", f"/tasks/{task_id}", body=changes, etag=etag)
        return self._task(data, task_id=task_id, write=True)

    def list_labels(self) -> list[dict[str, Any]]:
        """Read only labels visible to this bot; never assume instance-global access."""
        return self._list("/labels")

    def create_label(self, title: str) -> dict[str, Any]:
        """Create a label once; caller reconciles uncertain outcomes."""
        if not isinstance(title, str) or not title.strip() or len(title) > 250:
            raise TodoAPIError("Label title must contain one to 250 characters.")
        data, _ = self._request("POST", "/labels", body={"title": title})
        return self._resource(data, write=True)

    def assign_label(self, task_id: int, label_id: int) -> dict[str, Any]:
        """Attach one existing label without replacing any other task labels."""
        label_id = _id(label_id)
        data, _ = self._request(
            "POST", f"/tasks/{_id(task_id)}/labels", body={"label_id": label_id}
        )
        if type(data.get("label_id")) is not int or data["label_id"] != label_id:
            raise TodoWriteUncertainError(
                "Label assignment outcome unknown; reconcile before replay."
            )
        return data

    def create_relation(
        self, task_id: int, other_task_id: int, kind: str
    ) -> dict[str, Any]:
        """Relate two tasks; Vikunja creates the inverse automatically."""
        task_id, other_task_id = _id(task_id), _id(other_task_id)
        if (
            not isinstance(kind, str)
            or kind not in _RELATIONS
            or task_id == other_task_id
        ):
            raise TodoAPIError("Provide a supported relation between distinct tasks.")
        body = {"other_task_id": other_task_id, "relation_kind": kind}
        data, _ = self._request("POST", f"/tasks/{task_id}/relations", body=body)
        if (
            data.get("other_task_id") != other_task_id
            or data.get("relation_kind") != kind
            or data.get("task_id") != task_id
        ):
            raise TodoWriteUncertainError(
                "Relation outcome unknown; reconcile before replay."
            )
        return data

    def list_comments(self, task_id: int) -> list[dict[str, Any]]:
        """Read every comment on one task; fail rather than return partial data."""
        return self._list(f"/tasks/{_id(task_id)}/comments", parser=self._comment)

    def create_comment(self, task_id: int, comment: str) -> dict[str, Any]:
        """Append one plain-text comment; the caller reconciles uncertain outcomes."""
        if (
            not isinstance(comment, str)
            or not comment.strip()
            or len(comment) > 500_000
        ):
            raise TodoAPIError("Comment must contain one to 500000 characters.")
        body = {"comment": f"<pre>{html.escape(comment, quote=False)}</pre>"}
        data, _ = self._request("POST", f"/tasks/{_id(task_id)}/comments", body=body)
        return self._comment(data, write=True)
