"""
CYBER-RAG Engine
ChromaDB vector store + Ollama embeddings (nomic-embed-text)
Hybrid retrieval: vector similarity + BM25 re-ranking when rank-bm25 is installed.
"""
import hashlib
from typing import Any

import chromadb
import httpx

try:
    from rank_bm25 import BM25Okapi
    _HAS_BM25 = True
except ImportError:
    _HAS_BM25 = False


# ──────────────────────────────────────────────────────────
# Custom Embedding Function (Ollama)
# ──────────────────────────────────────────────────────────

class OllamaEmbeddingFunction:
    """Wraps the Ollama /api/embeddings endpoint for ChromaDB."""

    def __init__(self, model: str = "nomic-embed-text", host: str = "http://localhost:11434"):
        self.model = model
        self.host = host.rstrip("/")
        self._http = httpx.Client(timeout=60.0)

    # ChromaDB 1.5+ requires this method on any custom embedding function
    def name(self) -> str:
        return f"ollama-{self.model}"

    def _embed(self, texts: list[str]) -> list[list[float]]:
        embeddings: list[list[float]] = []
        for text in texts:
            resp = self._http.post(
                f"{self.host}/api/embeddings",
                json={"model": self.model, "prompt": text[:8000]},
            )
            resp.raise_for_status()
            embeddings.append(resp.json()["embedding"])
        return embeddings

    # ChromaDB 1.5+ calls __call__ for documents and embed_query for queries
    def __call__(self, input: list[str]) -> list[list[float]]:  # noqa: A002
        return self._embed(input)

    def embed_query(self, input: list[str]) -> list[list[float]]:  # noqa: A002
        return self._embed(input)


# ──────────────────────────────────────────────────────────
# RAG Engine
# ──────────────────────────────────────────────────────────

class RAGEngine:
    COLLECTION_NAME = "notion_notes"
    CHUNK_SIZE = 1400
    CHUNK_OVERLAP = 200

    def __init__(self, config: dict):
        self.config = config

        self.ef = OllamaEmbeddingFunction(
            model=config.get("embed_model", "nomic-embed-text"),
            host=config.get("ollama_host", "http://localhost:11434"),
        )

        self._client = chromadb.PersistentClient(path=config.get("chroma_path", "./chroma_db"))
        self._collection = self._get_or_create_collection()

    # ── Internal ──────────────────────────────────

    def _get_or_create_collection(self):
        return self._client.get_or_create_collection(
            name=self.COLLECTION_NAME,
            embedding_function=self.ef,
            metadata={"hnsw:space": "cosine"},
        )

    # ── Chunking ──────────────────────────────────

    def _chunk(self, text: str) -> list[str]:
        if len(text) <= self.CHUNK_SIZE:
            return [text] if text.strip() else []
        chunks: list[str] = []
        start = 0
        while start < len(text):
            end = start + self.CHUNK_SIZE
            chunks.append(text[start:end])
            start = end - self.CHUNK_OVERLAP
        return [c for c in chunks if c.strip()]

    @staticmethod
    def _chunk_id(doc_id: str, idx: int) -> str:
        return f"{doc_id}__chunk_{idx}"

    # ── Public API ────────────────────────────────

    def add_document(self, doc_id: str, content: str, metadata: dict) -> int:
        """Upsert a document (split into chunks). Returns number of chunks added."""
        if not content.strip():
            return 0

        chunks = self._chunk(content)
        ids, docs, metas = [], [], []

        for i, chunk in enumerate(chunks):
            cid = self._chunk_id(doc_id, i)
            meta = {**metadata, "chunk_idx": i, "total_chunks": len(chunks)}
            ids.append(cid)
            docs.append(chunk)
            metas.append(meta)

        self._collection.upsert(ids=ids, documents=docs, metadatas=metas)
        return len(chunks)

    def search(self, query: str, n: int = 6) -> list[dict[str, Any]]:
        """Hybrid search: fetch 2n vector candidates, re-rank with BM25, return top n."""
        total = self._collection.count()
        if total == 0:
            return []

        # Fetch more candidates than needed so BM25 can re-rank meaningfully
        k = min(max(n * 2, 10), total)
        results = self._collection.query(query_texts=[query], n_results=k)

        candidates: list[dict] = []
        for i in range(len(results["ids"][0])):
            candidates.append({
                "id":       results["ids"][0][i],
                "content":  results["documents"][0][i],
                "metadata": results["metadatas"][0][i],
                "vector_score": round(1 - results["distances"][0][i], 4),
            })

        if _HAS_BM25 and len(candidates) > 1:
            tokenized = [c["content"].lower().split() for c in candidates]
            bm25 = BM25Okapi(tokenized)
            bm25_scores = bm25.get_scores(query.lower().split())
            max_s = max(bm25_scores) if max(bm25_scores) > 0 else 1.0
            for c, s in zip(candidates, bm25_scores):
                c["bm25_score"] = s / max_s
                # 60% vector, 40% keyword — vector dominates but exact matches get a boost
                c["score"] = round(0.6 * c["vector_score"] + 0.4 * c["bm25_score"], 3)
        else:
            for c in candidates:
                c["score"] = c["vector_score"]

        return sorted(candidates, key=lambda x: x["score"], reverse=True)[:n]

    def count(self) -> int:
        return self._collection.count()

    def clear(self):
        """Wipe and recreate the collection."""
        self._client.delete_collection(self.COLLECTION_NAME)
        self._collection = self._get_or_create_collection()

    def get_stats(self) -> dict:
        return {"total_chunks": self.count(), "bm25": _HAS_BM25}
