from collections.abc import Iterable


class ChromaClient:
    """Small vector-store adapter; replace storage with ChromaDB when enabled."""

    def __init__(self):
        self._items: dict[str, dict] = {}

    def upsert(self, item_id: str, document: str, embedding: list[float], metadata: dict | None = None) -> None:
        self._items[item_id] = {"id": item_id, "document": document, "embedding": embedding, "metadata": metadata or {}}

    def get(self, item_id: str) -> dict | None:
        return self._items.get(item_id)

    def all(self) -> Iterable[dict]:
        return self._items.values()
