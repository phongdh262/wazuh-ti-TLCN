#!/usr/bin/env python3
"""Bo nho dem TTL an toan."""

import time
import threading

from config import CACHE_MAXSIZE, CACHE_TTL


class TTLCache:

    def __init__(self, maxsize=500, ttl=3600):
        self._store   = {}
        self._maxsize = maxsize
        self._ttl     = ttl
        self._lock    = threading.Lock()

    def _now(self):
        return time.monotonic()

    def _prune_expired_locked(self, now=None):
        now = self._now() if now is None else now
        expired = [key for key, (_, expire_at) in self._store.items() if expire_at <= now]
        for key in expired:
            self._store.pop(key, None)

    def get(self, key):
        with self._lock:
            item = self._store.get(key)
            if item is None:
                return None
            value, expire_at = item
            if expire_at <= self._now():
                self._store.pop(key, None)
                return None
            return value

    def set(self, key, value, ttl=None):
        with self._lock:
            now = self._now()
            self._prune_expired_locked(now)
            if key not in self._store and len(self._store) >= self._maxsize:
                oldest = min(self._store, key=lambda k: self._store[k][1])
                self._store.pop(oldest, None)
            expire_at = now + (self._ttl if ttl is None else ttl)
            self._store[key] = (value, expire_at)


cache = TTLCache(maxsize=CACHE_MAXSIZE, ttl=CACHE_TTL)
