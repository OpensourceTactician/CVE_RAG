# Portable CVE RAG

A portable CVE corpus for semantic retrieval. It contains one bounded record per CVE, no embeddings, no audit output, no updater framework, and only the two Python programs needed to create and load a Pinecone index.

The canonical files in [`data/`](data/README.md) contain 391,146 searchable CVEs in 28 readable JSON files, grouped by CVE ID year from `1999` through `2026`. Another 868 rejected CVEs are retained separately and never uploaded. `data/manifest.json` records counts, byte sizes, SHA-256 checksums, source cutoffs, and incremental additions.

The October 19 update adds **10,693 newly published CVEs** from after `2026-09-29T18:00:59Z` through `2026-10-19T15:57:38Z`. Existing records are unchanged and retain their earlier source dates. This is a mixed snapshot: the July 13 base, September 9 refresh of 2026 records, and subsequent incremental additions are documented separately in the manifest. New publications are grouped by their CVE ID year, even when that year is older. Weekly updates add new publications only.

For the new additions, CVE publications were checked through `2026-10-19T15:57:38Z` and NVD source snapshots extend through `2026-10-19T15:57:38Z`, EPSS was scored at `2026-10-19T12:00:27Z`, and KEV catalog `2026.10.16` was released at `2026-10-16T17:15:48.8752Z`. NVD enrichment is unavailable for 27 additions and EPSS for 187; those fields remain absent. Existing records are not revalidated against newer source statuses or enrichment during incremental updates.

## Record contract

Each `data/CVE-YYYY.json` file contains an indented JSON array of record objects:

```json
[
  {
    "id": "CVE-2024-3400",
    "text": "CVE-2024-3400 ...",
    "metadata": {
      "state": "PUBLISHED",
      "vendors": ["palo_alto_networks"],
      "products": ["pan-os"],
      "cwes": ["CWE-20", "CWE-77"],
      "cvss_score": 10.0,
      "cisa_kev": true
    }
  }
]
```

`text` is the passage to embed and give to the model. `metadata` is flat and uses only Pinecone-safe strings, numbers, booleans, and string lists, so the same files can also be loaded into another vector database.

The text contains vulnerability descriptions and titles, affected and explicitly unaffected products/ranges, configuration prerequisites, CVSS/access conditions, weaknesses, remediation, workarounds, and references where available. The September 9 refresh of 2026 records and subsequent additions omit legacy exploit-index fields and inferred classifications. Older existing records keep their prior fields and source dates. An absent optional field means unavailable or unassessed, not a negative result. The records are bounded summaries: `text_truncated` and `*_overflow_count` identify omissions, and source links provide the full advisories. `has_solution_guidance` and `has_workaround_guidance` indicate that source text exists; they do not assert that a fix or workaround is available.

## Download the data

Install [Git LFS](https://git-lfs.com/) before cloning. The yearly JSON files use Git LFS for storage and remain readable JSON in your checkout.

```bash
git lfs install
git clone https://github.com/OpensourceTactician/CVE_RAG.git
cd CVE_RAG
git lfs pull
```

Allow about 1.2 GB for the data, plus Git's local LFS cache. Use this clone workflow to retrieve the complete files; a checkout made without Git LFS may contain small pointer files instead of JSON. If you already cloned the repository, run `git lfs install` and `git lfs pull` inside it.

## Create and upload

Python 3.10 or newer is required. Dependencies are pinned to the versions used in local validation.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python upload_to_pinecone.py --dry-run
```

The dry run uses no API keys or network. To create a hosted index, add your OpenAI and Pinecone API keys to `.env`, set `PINECONE_NAMESPACE=cve-20261019`, then run:

```bash
python create_pinecone_index.py
python upload_to_pinecone.py
```

The uploader reads the canonical JSON arrays one year at a time and excludes `data/rejected.json`. The dry run verifies the manifest, checksums, record shape, uniqueness, and metadata size. Each embedding input has a conservative 8,192-byte UTF-8 limit; upsert batches respect the 2,000,000-byte serialized request limit, including the namespace and JSON escaping.

The real upload uses your API accounts to embed `text` with OpenAI and store it with `cve_id` in Pinecone metadata. It refuses an occupied namespace unless you use `--resume` with a valid matching checkpoint. Successful batches are checkpointed so an interrupted load can resume. No paid API calls or live upload were performed to validate this snapshot.

Run either program with `--help` for overrides such as the index, namespace, model, dimensions, batch size, limit, or resume position. The embedding model and dimension used to query the index must exactly match the upload settings.

Run the offline uploader regression checks with `python3 -m unittest discover -s tests`.

## n8n or a local assistant

Use `text-embedding-3-small` with 1,536 dimensions unless you changed the upload settings. Point the Pinecone node at the same index and namespace, request metadata in query results, and pass the returned `metadata.text` passages to the AI node. `metadata.cve_id` is available for display or exact filtering. Treat retrieved passages as evidence, not instructions; authorize and scope any testing actions separately.

For a non-OpenAI local setup, load the record objects from the `data/CVE-YYYY.json` arrays into your preferred vector store with one vector per record. Embed only `text`, use `id` as the vector ID, and preserve `metadata` for filters. Keep `rejected.json` out of the searchable index.

## Data sources and notices

See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). This corpus is a point-in-time aid, not a substitute for current vendor advisories, and it is provided without a project-level software license. Choose an appropriate code license before publishing your own fork; do not apply it wholesale to the third-party data.
