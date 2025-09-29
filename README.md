# CVE RAG System

A vector database for semantic search across 280,000+ Common Vulnerabilities and Exposures (CVE) records. Built with Pinecone and OpenAI embeddings.

---

## Overview

This repository provides pre-processed CVE data enriched with threat intelligence from multiple sources. Run two scripts to create a fully searchable vector database for vulnerability research, security automation, and RAG applications.

---

## Data Coverage

| Metric | Value |
|--------|-------|
| CVE Records | 280,000+ |
| Date Range | 1999 - 2025 |
| Data Sources | NVD, CISA KEV, EPSS, ExploitDB, Metasploit |

---

## CVE Data Schema

Each CVE record contains the following fields:

### Core Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | CVE identifier (e.g., CVE-2024-0012) |
| `embedding_input` | string | Full description text used for vector embedding |
| `datePublished` | string | Publication date (YYYY-MM-DD) |
| `cweId` | string | Common Weakness Enumeration ID |

### CVSS v3.1 Metrics

| Field | Type | Values |
|-------|------|--------|
| `baseScore` | float | 0.0 - 10.0 |
| `baseSeverity` | string | CRITICAL, HIGH, MEDIUM, LOW |
| `attackVector` | string | NETWORK, ADJACENT_NETWORK, LOCAL, PHYSICAL |
| `attackComplexity` | string | LOW, HIGH |
| `privilegesRequired` | string | NONE, LOW, HIGH |
| `userInteraction` | string | NONE, REQUIRED |
| `scope` | string | UNCHANGED, CHANGED |
| `confidentialityImpact` | string | NONE, LOW, HIGH |
| `integrityImpact` | string | NONE, LOW, HIGH |
| `availabilityImpact` | string | NONE, LOW, HIGH |

### Threat Intelligence

| Field | Type | Description |
|-------|------|-------------|
| `inCisaKev` | boolean | Listed in CISA Known Exploited Vulnerabilities catalog |
| `kevDateAdded` | string | Date added to KEV catalog |
| `kevDueDate` | string | Federal remediation deadline |
| `kevRansomwareUse` | string | Known ransomware campaign usage |
| `epssScore` | float | Exploit Prediction Scoring System probability (0-1) |
| `epssPercentile` | float | EPSS percentile rank (0-1) |

### Exploit Information

| Field | Type | Description |
|-------|------|-------------|
| `hasPublicExploit` | boolean | Public exploit code exists (ExploitDB) |
| `exploitCount` | integer | Number of public exploits available |
| `hasMetasploitModule` | boolean | Metasploit module available |
| `metasploitModuleCount` | integer | Number of Metasploit modules |
| `metasploitModules` | array | Module details (path, name, type, rank, platforms) |

---

## Quick Start

### Prerequisites

- Python 3.7+
- OpenAI API key ([get one here](https://platform.openai.com/))
- Pinecone API key ([get one here](https://www.pinecone.io/))

### Installation

```bash
git clone https://github.com/your-username/CVE_RAG.git
cd CVE_RAG
pip install pinecone openai python-dotenv
```

### Configuration

Create a `.env` file in the project root:

```
OPENAI_API_KEY=sk-...
PINECONE_API_KEY=...
```

Or export as environment variables:

```bash
# Linux/macOS
export OPENAI_API_KEY="sk-..."
export PINECONE_API_KEY="..."

# Windows PowerShell
$env:OPENAI_API_KEY="sk-..."
$env:PINECONE_API_KEY="..."
```

### Create the Database

**Step 1:** Initialize the Pinecone index

```bash
python pinecone_initializer.py
```

**Step 2:** Embed and upload CVE data

```bash
python embed_upload.py
```

The upload process takes 1-3 hours for the full dataset.

---

## Project Structure

```
CVE_RAG/
├── CVE_List/                    # Pre-processed CVE data
│   ├── 1999/cves_1999.json
│   ├── 2000/cves_2000.json
│   └── .../cves_YYYY.json
├── pinecone_initializer.py      # Creates Pinecone index
├── embed_upload.py              # Embeds and uploads CVEs
├── cve_payload.py               # Data loading utilities
└── README.md
```

---

## Configuration Options

### Index Settings

Edit `pinecone_initializer.py`:

```python
index_name = "cve-rag"      # Index name
dimension = 1536            # Vector dimensions (OpenAI text-embedding-3-small)
metric = "cosine"           # Similarity metric
```

### Upload Settings

Edit `embed_upload.py`:

```python
batch_size = 100            # CVEs per batch
delay = 1.0                 # Seconds between batches
```

---

## Data Sources

| Source | Description | Update Frequency |
|--------|-------------|------------------|
| [NVD](https://nvd.nist.gov/) | CVSS scores, CWE mappings, CPE data | Continuous |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Known exploited vulnerabilities | As identified |
| [EPSS](https://www.first.org/epss/) | Exploit prediction scores | Daily |
| [ExploitDB](https://www.exploit-db.com/) | Public exploit references | Continuous |
| [Metasploit](https://www.metasploit.com/) | Framework module mappings | Weekly |

---

## Security

- Never commit API keys to version control
- The `.gitignore` excludes `.env` and credential files
- Rotate API keys periodically
