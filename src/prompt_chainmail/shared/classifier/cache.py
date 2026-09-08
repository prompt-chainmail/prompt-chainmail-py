from __future__ import annotations


class BoundedCache[K, V]:
    """Bounded LRU cache for repeated classification of the same sanitized text."""

    def __init__(self, max_entries: int) -> None:
        if max_entries <= 0:
            raise ValueError("maxEntries must be a positive integer")
        self._max_entries = max_entries
        self._order: list[K] = []
        self._store: dict[K, V] = {}

    def get(self, key: K) -> V | None:
        if key not in self._store:
            return None
        self._order = [item for item in self._order if item != key]
        self._order.append(key)
        return self._store[key]

    def set(self, key: K, value: V) -> None:
        if key in self._store:
            self._order = [item for item in self._order if item != key]
        elif len(self._store) >= self._max_entries:
            oldest = self._order[0]
            del self._order[0]
            del self._store[oldest]
        self._order.append(key)
        self._store[key] = value

    def has(self, key: K) -> bool:
        return key in self._store

    def size(self) -> int:
        return len(self._store)

    def clear(self) -> None:
        self._order.clear()
        self._store.clear()
