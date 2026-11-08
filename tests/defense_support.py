"""Deterministic fakes used by the defensive-action tests.

Nothing here runs a real command and nothing touches real firewall state.
"""

from __future__ import annotations

import os

from defense import policy
from defense.service import DefenseService

TASKLIST_CSV = (
    '"chrome.exe","1234","Console","1","100,000 K"\n'
    '"python.exe","5678","Console","1","80,000 K"\n'
)

NETSTAT_TEXT = """Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    127.0.0.1:5000         0.0.0.0:0              LISTENING       1234
  TCP    10.0.0.5:49152         203.0.113.7:443        ESTABLISHED     5678
  UDP    0.0.0.0:5353           *:*                                    1234
"""

FIREWALL_TEXT = """Domain Profile Settings:
----------------------------------------------------------------------
State                                 ON

Private Profile Settings:
----------------------------------------------------------------------
State                                 OFF

Public Profile Settings:
----------------------------------------------------------------------
State                                 ON
"""


class Clock:
    def __init__(self, now=1_700_000_000.0):
        self.now = float(now)

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += float(seconds)
        return self.now


class Completed:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr

    @classmethod
    def ok(cls, stdout=""):
        return cls(0, stdout, "")

    @classmethod
    def fail(cls, code=1, stderr="command failed"):
        return cls(code, "", stderr)


def default_runner(argv, **kwargs):
    name = os.path.basename(str(argv[0])).lower()
    if name == "tasklist.exe" or name == "tasklist":
        return Completed.ok(TASKLIST_CSV)
    if name == "netstat.exe" or name == "netstat":
        return Completed.ok(NETSTAT_TEXT)
    if name == "netsh.exe" or name == "netsh":
        return Completed.ok(FIREWALL_TEXT)
    return Completed.fail(1, "unexpected command")


class RecordingRunner:
    """Records argv calls and returns canned results."""

    def __init__(self, results=None, default=None):
        self.calls = []
        self.results = results or {}
        self.default = default or Completed.ok("")

    def __call__(self, argv, **kwargs):
        self.calls.append(list(argv))
        return self.results.get(tuple(argv), self.default)


class FakeElevation:
    """Stand-in for the UAC adapter; never elevates anything."""

    name = "fake-uac"

    def __init__(self, result=None, enabled=True):
        self.calls = []
        self.result = result
        self.enabled = bool(enabled)

    def status(self):
        return {
            "supported": True,
            "enabled": self.enabled,
            "adapter": self.name,
            "detail": "test adapter",
        }

    def execute(self, action_type, params, action_id):
        self.calls.append((action_type, dict(params), action_id))
        if self.result is not None:
            return dict(self.result)

        detail = {}
        if action_type == "create_firewall_block_rule":
            detail["rule_name"] = policy.rule_name_for(params)

        return {
            "status": "success",
            "changed": True,
            "verified": True,
            "error": None,
            "error_category": None,
            "elevation": "used",
            "detail": detail,
        }


def make_service(tmp_path, clock, elevation=None, inspection_runner=None,
                 firewall_runner=None):
    return DefenseService(
        base_dir=tmp_path / "defense",
        clock=clock,
        elevation=elevation or FakeElevation(),
        inspection_runner=inspection_runner or default_runner,
        firewall_runner=firewall_runner or default_runner,
    )


class CsrfClient:
    """Flask test client that bootstraps and sends the session CSRF token.

    The defensive API rejects every state-changing request without a
    session-bound token, so tests must behave like the dashboard: fetch
    ``/api/defense/status`` once and send the returned token on later writes.
    """

    def __init__(self, inner):
        self._inner = inner
        self.csrf_token = None
        self.csrf_header = "X-CyberGuard-CSRF"
        self.bootstrap()

    def bootstrap(self):
        response = self._inner.get("/api/defense/status")
        data = response.get_json() or {}
        self.csrf_token = data.get("csrf_token") or self.csrf_token
        self.csrf_header = data.get("csrf_header") or self.csrf_header
        return response

    def _with_csrf(self, kwargs):
        kwargs = dict(kwargs)
        headers = dict(kwargs.pop("headers", None) or {})
        if self.csrf_token:
            headers.setdefault(self.csrf_header, self.csrf_token)
        kwargs["headers"] = headers
        return kwargs

    def post(self, *args, **kwargs):
        return self._inner.post(*args, **self._with_csrf(kwargs))

    def put(self, *args, **kwargs):
        return self._inner.put(*args, **self._with_csrf(kwargs))

    def patch(self, *args, **kwargs):
        return self._inner.patch(*args, **self._with_csrf(kwargs))

    def delete(self, *args, **kwargs):
        return self._inner.delete(*args, **self._with_csrf(kwargs))

    def get(self, *args, **kwargs):
        return self._inner.get(*args, **kwargs)

    def __getattr__(self, name):
        return getattr(self._inner, name)


VALID_BLOCK = {
    "remote_address": "203.0.113.7",
    "local_port": 22,
    "protocol": "tcp",
    "profile": "any",
    "lifetime_minutes": 30,
}
