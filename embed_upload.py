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

def get_embedding(text: str, model: str = "text-embedding-3-small") -> List[float]:
    """Generate embedding for the given text."""
    response = openai.embeddings.create(input=[text], model=model)
    return response.data[0].embedding

def batch_upload_cves(batch_size: int = 100, delay: float = 1.0) -> None:
    """
    Upload all CVEs to Pinecone in batches.

    Args:
        batch_size: Number of CVEs to upload in each batch
        delay: Delay in seconds between batches to avoid rate limits
    """
    total_cves = get_cve_count()
    print(f"Total CVEs to upload: {total_cves}")

    uploaded_count = 0
    batch = []

    for cve_data in load_cves_from_directory():
        if not cve_data.get('id') or not cve_data.get('embedding_input'):
            print(f"[WARN] Skipping CVE with missing id or embedding_input")
            continue

        try:
            # Generate embedding
            vector = get_embedding(cve_data['embedding_input'])

            # Prepare for batch upload
            batch.append({
                "id": cve_data['id'],
                "values": vector,
                "metadata": cve_data['metadata']
            })

            # Upload batch when it reaches the specified size
            if len(batch) >= batch_size:
                index.upsert(batch)
                uploaded_count += len(batch)
                print(f"[OK] Uploaded batch of {len(batch)} CVEs ({uploaded_count}/{total_cves})")
                batch = []

                # Add delay to avoid rate limits
                if delay > 0:
                    time.sleep(delay)

        except Exception as e:
            print(f"[ERR] Error processing {cve_data.get('id', 'unknown')}: {e}")
            continue

    # Upload remaining CVEs in the last batch
    if batch:
        try:
            index.upsert(batch)
            uploaded_count += len(batch)
            print(f"[OK] Uploaded final batch of {len(batch)} CVEs ({uploaded_count}/{total_cves})")
        except Exception as e:
            print(f"[ERR] Error uploading final batch: {e}")

    print(f"Upload complete! Successfully uploaded {uploaded_count} CVEs to Pinecone index 'cve-rag'")

if __name__ == "__main__":
    batch_upload_cves()
