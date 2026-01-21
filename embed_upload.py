import os
import openai
from pinecone import Pinecone
from cve_payload import load_cves_from_directory, get_cve_count
import time
from typing import List, Dict, Any
from dotenv import load_dotenv

# Load .env file
load_dotenv()

# Load keys
openai.api_key = os.getenv("OPENAI_API_KEY")
pinecone_api_key = os.getenv("PINECONE_API_KEY")

if not openai.api_key:
    raise RuntimeError("OPENAI_API_KEY environment variable is not set")
if not pinecone_api_key:
    raise RuntimeError("PINECONE_API_KEY environment variable is not set")

# Connect to Pinecone
pc = Pinecone(api_key=pinecone_api_key)
index = pc.Index("cve-rag")


def get_embeddings_batch(texts: List[str], model: str = "text-embedding-3-small") -> List[List[float]]:
    """Generate embeddings for multiple texts in one API call."""
    response = openai.embeddings.create(input=texts, model=model)
    return [item.embedding for item in response.data]


def batch_upload_cves(batch_size: int = 100, embedding_batch_size: int = 500) -> None:
    """
    Upload all CVEs to Pinecone in batches with batched embedding generation.

    Args:
        batch_size: Number of CVEs to upsert to Pinecone at once
        embedding_batch_size: Number of embeddings to generate in one OpenAI call
    """
    total_cves = get_cve_count()
    print(f"Total CVEs to upload: {total_cves}")
    print(f"Embedding batch size: {embedding_batch_size}, Pinecone batch size: {batch_size}")

    uploaded_count = 0
    pending_cves = []

    for cve_data in load_cves_from_directory():
        if not cve_data.get('id') or not cve_data.get('embedding_input'):
            continue

        pending_cves.append(cve_data)

        # Process when we have enough for an embedding batch
        if len(pending_cves) >= embedding_batch_size:
            uploaded_count = process_batch(pending_cves, uploaded_count, total_cves, batch_size)
            pending_cves = []

    # Process remaining CVEs
    if pending_cves:
        uploaded_count = process_batch(pending_cves, uploaded_count, total_cves, batch_size)

    print(f"Upload complete! Successfully uploaded {uploaded_count} CVEs to Pinecone index 'cve-rag'")


def process_batch(cves: List[Dict], uploaded_count: int, total_cves: int, pinecone_batch_size: int) -> int:
    """Process a batch of CVEs - generate embeddings and upload to Pinecone."""
    try:
        # Generate all embeddings in one call
        texts = [cve['embedding_input'] for cve in cves]
        embeddings = get_embeddings_batch(texts)

        # Prepare vectors for Pinecone
        vectors = []
        for cve, embedding in zip(cves, embeddings):
            vectors.append({
                "id": cve['id'],
                "values": embedding,
                "metadata": cve['metadata']
            })

        # Upsert to Pinecone in chunks
        for i in range(0, len(vectors), pinecone_batch_size):
            chunk = vectors[i:i + pinecone_batch_size]
            index.upsert(chunk)
            uploaded_count += len(chunk)
            print(f"[OK] Uploaded {uploaded_count}/{total_cves} ({100*uploaded_count/total_cves:.1f}%)")

    except Exception as e:
        print(f"[ERR] Error processing batch: {e}")

    return uploaded_count


if __name__ == "__main__":
    batch_upload_cves(batch_size=100, embedding_batch_size=1000)
