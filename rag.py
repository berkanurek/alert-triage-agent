"""RAG over the security playbooks.

1. Chunking:   every playbook is split into its sections (When to use / Investigation / Response).
2. Embedding:  every chunk is turned into a vector with a Gemini embedding model.
3. Index:      the vectors are saved in data/playbook_index.json, so we only embed again
               when a playbook changes (saves API quota).
4. Retrieval:  the alert is embedded too, and we return the chunks whose vectors are
               most similar to it (cosine similarity, top-k).

For 7 playbooks a JSON file is enough. In production you would use a vector database
such as pgvector or Chroma, but the idea is exactly the same.
"""

import hashlib
import json
from pathlib import Path

import numpy as np
from google import genai
from google.genai import types

from triage import call_with_retry

PLAYBOOK_DIR = Path(__file__).parent / "playbooks"
INDEX_FILE = Path(__file__).parent / "data" / "playbook_index.json"
EMBEDDING_MODEL = "gemini-embedding-001"
DIMENSIONS = 768


def chunk_playbooks() -> list[dict]:
    """Split every playbook into sections. Each chunk keeps its playbook title for context."""
    chunks = []
    for path in sorted(PLAYBOOK_DIR.glob("*.md")):
        text = path.read_text(encoding="utf-8")
        title = text.splitlines()[0].lstrip("# ").strip()  # e.g. "PB-01 Password guessing and account takeover"
        for section in text.split("\n## ")[1:]:
            heading, _, body = section.partition("\n")
            chunks.append({
                "id": f"{title.split()[0]} / {heading.strip()}",  # e.g. "PB-01 / Response"
                "text": f"{title}. {heading.strip()}: {body.strip()}",
            })
    return chunks


def _embed(client: genai.Client, texts: list[str], task_type: str) -> np.ndarray:
    result = call_with_retry(lambda: client.models.embed_content(
        model=EMBEDDING_MODEL,
        contents=texts,
        config=types.EmbedContentConfig(task_type=task_type, output_dimensionality=DIMENSIONS),
    ))
    vectors = np.array([e.values for e in result.embeddings])
    return vectors / np.linalg.norm(vectors, axis=1, keepdims=True)  # normalize -> dot product = cosine similarity


def load_index(client: genai.Client) -> dict:
    """Load the saved index, or build it again if any playbook changed."""
    chunks = chunk_playbooks()
    fingerprint = hashlib.sha256(json.dumps(chunks).encode()).hexdigest()
    if INDEX_FILE.exists():
        index = json.loads(INDEX_FILE.read_text(encoding="utf-8"))
        if index["fingerprint"] == fingerprint:
            return index
    print(f"   (building playbook index: embedding {len(chunks)} chunks...)")
    vectors = _embed(client, [c["text"] for c in chunks], "RETRIEVAL_DOCUMENT")
    index = {"fingerprint": fingerprint, "chunks": chunks, "vectors": vectors.tolist()}
    INDEX_FILE.write_text(json.dumps(index), encoding="utf-8")
    return index


def retrieve(client: genai.Client, query: str, k: int = 3) -> list[dict]:
    """Return the k playbook chunks most similar to the query, with their similarity score."""
    index = load_index(client)
    query_vector = _embed(client, [query], "RETRIEVAL_QUERY")[0]
    scores = np.array(index["vectors"]) @ query_vector
    best = np.argsort(scores)[::-1][:k]
    return [{**index["chunks"][i], "score": round(float(scores[i]), 3)} for i in best]


def format_for_prompt(chunks: list[dict]) -> str:
    return "\n\n".join(f"[{c['id']}] {c['text']}" for c in chunks)


if __name__ == "__main__":
    # Quick demo: python rag.py "large upload to personal dropbox by a leaving employee"
    import sys

    from dotenv import load_dotenv

    load_dotenv()
    question = " ".join(sys.argv[1:]) or "large upload to personal dropbox by a leaving employee"
    print(f"Query: {question}\n")
    for chunk in retrieve(genai.Client(), question):
        print(f"{chunk['score']:.3f}  {chunk['id']}")
