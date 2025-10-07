"""In-memory session state store keyed by sessionId."""
from __future__ import annotations

import copy
import threading
import time
from typing import Dict

from .spec_loader import Scenario


class SessionStateStore:
    """Store per-session state per scenario slug."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._sessions: Dict[str, Dict[str, object]] = {}
        self._max_age = 1800  # seconds

    def _key(self, slug: str, session_id: str) -> str:
        return f"{slug}:{session_id}"

    def get_state(self, slug: str, session_id: str, scenario: Scenario) -> Dict[str, object]:
        """Return a deep copy of the state for the session, creating if needed."""
        key = self._key(slug, session_id)
        with self._lock:
            ctx = self._sessions.get(key)
            now = time.time()
            if (
                ctx is None
                or ctx.get("scenario_slug") != slug
                or now - ctx.get("created", 0) > self._max_age
            ):
                state = scenario.fresh_state()
                ctx = {
                    "scenario_slug": slug,
                    "state": state,
                    "created": now,
                    "updated": now,
                }
                self._sessions[key] = ctx
            return copy.deepcopy(ctx["state"])  # Prevent callers from mutating in-place.

    def update_state(self, slug: str, session_id: str, scenario: Scenario, state: Dict[str, object]) -> None:
        key = self._key(slug, session_id)
        with self._lock:
            now = time.time()
            self._sessions[key] = {
                "scenario_slug": slug,
                "state": copy.deepcopy(state),
                "created": self._sessions.get(key, {}).get("created", now),
                "updated": now,
            }

    def ensure_session(self, slug: str, session_id: str, scenario: Scenario) -> None:
        """Ensure a session exists without returning its state."""
        self.get_state(slug, session_id, scenario)

    def reset_all(self) -> None:
        with self._lock:
            self._sessions.clear()

    def reset_slug(self, slug: str) -> None:
        prefix = f"{slug}:"
        with self._lock:
            for key in list(self._sessions.keys()):
                if key.startswith(prefix):
                    self._sessions.pop(key, None)
