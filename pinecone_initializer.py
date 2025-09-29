import os
from pinecone import Pinecone, ServerlessSpec
import time

def initialize_pinecone_index(
    index_name: str = "cve-rag",
    dimension: int = 1536,
    metric: str = "cosine",
    cloud: str = "aws",
    region: str = "us-east-1"
) -> None:
    """
    Initialize Pinecone client and create index if it doesn't exist.

    Args:
        index_name: Name of the Pinecone index
        dimension: Vector dimension (1536 for text-embedding-3-small)
        metric: Distance metric for the index
        cloud: Cloud provider for serverless deployment
        region: Cloud region for serverless deployment
    """
    # Read API key from environment
    api_key = os.getenv("PINECONE_API_KEY")
    if not api_key:
        raise RuntimeError("PINECONE_API_KEY environment variable is not set")

    # Initialize client
    pc = Pinecone(api_key=api_key)
    print("✅ Pinecone client initialized successfully")

    # Check if index already exists
    existing_indexes = [index.name for index in pc.list_indexes()]

    if index_name in existing_indexes:
        print(f"ℹ️  Index '{index_name}' already exists")

        # Get index stats
        index = pc.Index(index_name)
        stats = index.describe_index_stats()
        print(f"📊 Current index stats: {stats.total_vector_count} vectors")
        return

    # Create index if it doesn't exist
    print(f"🔨 Creating new index '{index_name}'...")
    pc.create_index(
        name=index_name,
        dimension=dimension,
        metric=metric,
        spec=ServerlessSpec(
            cloud=cloud,
            region=region
        )
    )

    # Wait for index to be ready
    print("⏳ Waiting for index to be ready...")
    while not pc.describe_index(index_name).status['ready']:
        time.sleep(1)

    print(f"✅ Index '{index_name}' created and ready!")

def delete_index(index_name: str = "cve-rag") -> None:
    """
    Delete a Pinecone index.

    Args:
        index_name: Name of the index to delete
    """
    api_key = os.getenv("PINECONE_API_KEY")
    if not api_key:
        raise RuntimeError("PINECONE_API_KEY environment variable is not set")

    pc = Pinecone(api_key=api_key)

    existing_indexes = [index.name for index in pc.list_indexes()]

    if index_name not in existing_indexes:
        print(f"ℹ️  Index '{index_name}' does not exist")
        return

    pc.delete_index(index_name)
    print(f"🗑️  Index '{index_name}' deleted successfully")

if __name__ == "__main__":
    initialize_pinecone_index()

