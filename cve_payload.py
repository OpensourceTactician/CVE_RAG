import json
import os
from typing import Generator, Dict, Any, List


def sanitize_metadata(metadata: Dict[str, Any]) -> Dict[str, Any]:
    """
    Sanitize metadata for Pinecone compatibility.
    Pinecone only supports: strings, numbers, booleans, and lists of strings.
    """
    sanitized = {}

    # Fields to exclude (contain nested objects)
    exclude_fields = {'exploits', 'metasploitModules', 'affectedProducts'}

    for key, value in metadata.items():
        if key in exclude_fields:
            continue

        # Handle different types
        if value is None:
            continue
        elif isinstance(value, (str, int, float, bool)):
            sanitized[key] = value
        elif isinstance(value, list):
            if len(value) == 0:
                continue
            # Check if it's a list of strings
            if all(isinstance(item, str) for item in value):
                sanitized[key] = value
            # Convert list of dicts to list of strings if possible
            elif all(isinstance(item, dict) for item in value):
                # Extract meaningful string representation
                string_list = []
                for item in value:
                    if 'id' in item:
                        string_list.append(str(item['id']))
                    elif 'name' in item:
                        string_list.append(str(item['name']))
                    elif 'vendor' in item and 'product' in item:
                        string_list.append(f"{item['vendor']}:{item['product']}")
                if string_list:
                    sanitized[key + '_list'] = string_list[:50]  # Limit list size
        elif isinstance(value, dict):
            # Skip nested dicts
            continue

    return sanitized


def load_cves_from_directory(cve_dir: str = "CVE_List") -> Generator[Dict[str, Any], None, None]:
    """
    Load CVEs from all JSON files in the CVE_List directory structure.

    Args:
        cve_dir: Path to the directory containing CVE JSON files

    Yields:
        Dict containing CVE data with id, embedding_input, and metadata
    """
    if not os.path.exists(cve_dir):
        raise FileNotFoundError(f"CVE directory '{cve_dir}' not found")

    for year_dir in sorted(os.listdir(cve_dir)):
        year_path = os.path.join(cve_dir, year_dir)

        if not os.path.isdir(year_path):
            continue

        json_file = os.path.join(year_path, f"cves_{year_dir}.json")

        if not os.path.exists(json_file):
            print(f"Warning: No CVE file found for year {year_dir}")
            continue

        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            cves = data.get('cves', [])
            print(f"Loading {len(cves)} CVEs from {year_dir}")

            for cve in cves:
                yield {
                    'id': cve.get('id'),
                    'embedding_input': cve.get('embedding_input'),
                    'metadata': sanitize_metadata(cve.get('metadata', {}))
                }

        except (json.JSONDecodeError, KeyError, IOError) as e:
            print(f"Error loading CVEs from {json_file}: {e}")
            continue


def get_cve_count(cve_dir: str = "CVE_List") -> int:
    """
    Get total count of CVEs across all years.

    Args:
        cve_dir: Path to the directory containing CVE JSON files

    Returns:
        Total number of CVEs
    """
    total_count = 0

    for year_dir in os.listdir(cve_dir):
        year_path = os.path.join(cve_dir, year_dir)

        if not os.path.isdir(year_path):
            continue

        json_file = os.path.join(year_path, f"cves_{year_dir}.json")

        if os.path.exists(json_file):
            try:
                with open(json_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                total_count += len(data.get('cves', []))
            except (json.JSONDecodeError, IOError):
                continue

    return total_count


# For backward compatibility with the original embed_upload script
# This will be updated when we modify embed_upload to use the generator
cve = None