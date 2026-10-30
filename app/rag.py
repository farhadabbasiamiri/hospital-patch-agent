"""Policy RAG: retrieves hospital change/downtime/medical-device policy sections.

Each policy is split into sections ("## §3 ...") and every chunk keeps a citation id such
as "POL-04 §2". Backends:
  tfidf      - scikit-learn TF-IDF + cosine similarity. No downloads, always works.
  embeddings - sentence-transformers dense embeddings (e.g. BGE-small). Set RAG_BACKEND=embeddings.
"""
import re
from functools import lru_cache

import numpy as np

from app.config import POLICY_DIR, RAG_BACKEND, EMBED_MODEL


def load_chunks() -> list[dict]:
    chunks = []
    for path in sorted(POLICY_DIR.glob("POL-*.md")):
        text = path.read_text()
        doc_id = path.name.split("_")[0]
        title = text.splitlines()[0].lstrip("# ").strip()
        for m in re.finditer(r"^## (§\d+) (.+?)\n(.*?)(?=^## |\Z)", text, flags=re.S | re.M):
            sec, heading, body = m.group(1), m.group(2).strip(), m.group(3).strip()
            chunks.append({
                "chunk_id": f"{doc_id} {sec}",
                "policy": title,
                "heading": heading,
                "text": body,
            })
    return chunks


class PolicyIndex:
    def __init__(self, backend: str = RAG_BACKEND):
        self.chunks = load_chunks()
        self.backend = backend
        docs = [f"{c['policy']} {c['heading']}. {c['text']}" for c in self.chunks]
        if backend == "embeddings":
            from sentence_transformers import SentenceTransformer
            self.model = SentenceTransformer(EMBED_MODEL)
            self.matrix = self.model.encode(docs, normalize_embeddings=True)
        else:
            from sklearn.feature_extraction.text import TfidfVectorizer
            self.vec = TfidfVectorizer(stop_words="english", ngram_range=(1, 2), sublinear_tf=True)
            self.matrix = self.vec.fit_transform(docs)

    def search(self, query: str, k: int = 3) -> list[dict]:
        if self.backend == "embeddings":
            q = self.model.encode([query], normalize_embeddings=True)
            sims = (self.matrix @ q.T).ravel()
        else:
            sims = (self.matrix @ self.vec.transform([query]).T).toarray().ravel()
        top = np.argsort(-sims)[:k]
        return [{**self.chunks[i], "score": round(float(sims[i]), 3)} for i in top if sims[i] > 0]

    def get(self, chunk_id: str) -> dict | None:
        return next((c for c in self.chunks if c["chunk_id"] == chunk_id), None)


@lru_cache(maxsize=1)
def get_index() -> PolicyIndex:
    return PolicyIndex()
