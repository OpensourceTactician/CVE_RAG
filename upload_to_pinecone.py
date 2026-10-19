#!/usr/bin/env python3
"""Validate, embed, and upload the portable CVE records to Pinecone."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from collections.abc import Mapping
from typing import Any, Callable, Iterable, Iterator, Sequence, TypeVar


ROOT = Path(__file__).resolve().parent
ID_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
MAX_METADATA_BYTES = 39_000
DEFAULT_UPSERT_BYTES = 1_800_000
MAX_UPSERT_BYTES = 2_000_000
MAX_UPSERT_VECTORS = 1_000
MAX_EMBED_INPUTS = 2_048
# UTF-8 byte counts upper-bound tokens for the supported byte-BPE models.
# This deliberately rejects some long texts that a tokenizer could accept.
MAX_EMBED_INPUT_BYTES = 8_192
MAX_EMBED_REQUEST_BYTES = 300_000
EMBED_MODEL_DIMENSIONS = {"text-embedding-3-small": 1_536, "text-embedding-3-large": 3_072}
T = TypeVar("T")


def load_env(path: Path) -> None:
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip()
        if value[:1] == value[-1:] and value[:1] in {"'", '"'}:
            value = value[1:-1]
        if key:
            os.environ.setdefault(key, value)


def positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def arguments() -> argparse.Namespace:
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--env-file", type=Path, default=ROOT / ".env")
    known, _ = pre.parse_known_args()
    load_env(known.env_file.expanduser())

    p = argparse.ArgumentParser(
        parents=[pre],
        description="Validate portable CVE JSON arrays, embed their text, and upsert stable CVE IDs.",
    )
    p.add_argument("--manifest", type=Path, default=ROOT / "data" / "manifest.json")
    p.add_argument("--index", default=os.getenv("PINECONE_INDEX_NAME", "cve-rag"))
    p.add_argument("--namespace", default=os.getenv("PINECONE_NAMESPACE", "cve-20261019"))
    p.add_argument("--model", default=os.getenv("OPENAI_EMBED_MODEL", "text-embedding-3-small"))
    p.add_argument(
        "--dimension",
        type=positive_int,
        default=positive_int(os.getenv("OPENAI_EMBED_DIMENSION", "1536")),
    )
    p.add_argument("--batch-size", type=positive_int, default=100, help="texts per embedding request")
    p.add_argument(
        "--upsert-max-bytes",
        type=positive_int,
        default=DEFAULT_UPSERT_BYTES,
        help="conservative serialized vector budget per Pinecone request",
    )
    p.add_argument("--retries", type=positive_int, default=5)
    p.add_argument("--limit", type=positive_int, help="upload at most this many records")
    p.add_argument("--start-after", help="skip through this exact CVE ID")
    p.add_argument("--resume", action="store_true", help="resume after the last successful checkpoint ID")
    p.add_argument("--checkpoint", type=Path, default=ROOT / ".upload-checkpoint.json")
    p.add_argument("--dry-run", action="store_true", help="fully validate locally; use no keys or network")
    args = p.parse_args()
    if args.resume and args.start_after:
        p.error("--resume and --start-after cannot be used together")
    if not args.index.strip() or not args.model.strip():
        p.error("index and embedding model cannot be empty")
    if args.upsert_max_bytes > MAX_UPSERT_BYTES:
        p.error("--upsert-max-bytes must stay at or below 2,000,000")
    if args.batch_size > MAX_EMBED_INPUTS:
        p.error("--batch-size must stay at or below 2,048")
    try:
        validate_embedding_settings(args.model, args.dimension)
    except ValueError as exc:
        p.error(str(exc))
    return args


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def compact_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def validate_embedding_settings(model: str, dimension: int) -> None:
    maximum = EMBED_MODEL_DIMENSIONS.get(model)
    if maximum is None:
        raise ValueError("embedding model must be text-embedding-3-small or text-embedding-3-large")
    if not 1 <= dimension <= maximum:
        raise ValueError(f"{model} requires dimensions between 1 and {maximum:,}")


def embedding_input_bytes(cve_id: str, text: str) -> int:
    size = len(text.encode("utf-8"))
    if size > MAX_EMBED_INPUT_BYTES:
        raise ValueError(
            f"{cve_id}: text is {size:,} UTF-8 bytes, above the conservative "
            f"{MAX_EMBED_INPUT_BYTES:,}-byte embedding input budget; shorten the text "
            "or validate it with an exact tokenizer before adapting this limit"
        )
    return size


def safe_data_path(root: Path, raw: object) -> Path:
    if not isinstance(raw, str) or not raw:
        raise ValueError("manifest file path must be a non-empty string")
    relative = Path(raw)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"unsafe manifest file path: {raw!r}")
    resolved = (root / relative).resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError as exc:
        raise ValueError(f"manifest path leaves data directory: {raw!r}") from exc
    return resolved


def validate_metadata(cve_id: str, metadata: object, text: str) -> int:
    if not isinstance(metadata, dict):
        raise ValueError(f"{cve_id}: metadata must be an object")
    reserved = {"text", "cve_id"} & set(metadata)
    if reserved:
        raise ValueError(f"{cve_id}: reserved uploader metadata key(s): {sorted(reserved)}")
    for key, value in metadata.items():
        if not isinstance(key, str) or not key or key.startswith("$"):
            raise ValueError(f"{cve_id}: invalid metadata key {key!r}")
        if isinstance(value, bool) or isinstance(value, str):
            continue
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            if not math.isfinite(float(value)):
                raise ValueError(f"{cve_id}: metadata.{key} is not finite")
            continue
        if isinstance(value, list) and value and all(isinstance(item, str) for item in value):
            continue
        raise ValueError(
            f"{cve_id}: metadata.{key} must be a string, finite number, boolean, or non-empty string list"
        )
    stored = dict(metadata)
    stored["text"] = text
    stored["cve_id"] = cve_id
    size = len(compact_bytes(stored))
    if size > MAX_METADATA_BYTES:
        raise ValueError(f"{cve_id}: stored metadata is {size:,} bytes; limit is {MAX_METADATA_BYTES:,}")
    return size


def validate_record(record: object, location: str, *, searchable: bool) -> tuple[str, int, int]:
    if not isinstance(record, dict) or set(record) != {"id", "text", "metadata"}:
        raise ValueError(f"{location}: record must contain exactly id, text, and metadata")
    cve_id = record["id"]
    text = record["text"]
    if not isinstance(cve_id, str) or not ID_RE.fullmatch(cve_id):
        raise ValueError(f"{location}: invalid CVE ID {cve_id!r}")
    if not isinstance(text, str) or not text.strip():
        raise ValueError(f"{cve_id}: text must be a non-empty string")
    metadata = record["metadata"]
    state = str(metadata.get("state", "")).upper() if isinstance(metadata, dict) else ""
    if searchable and state == "REJECTED":
        raise ValueError(f"{cve_id}: rejected record appeared in a searchable file")
    if not searchable and state != "REJECTED":
        raise ValueError(f"{cve_id}: non-rejected record appeared in the rejected file")
    metadata_size = validate_metadata(cve_id, metadata, text)
    if searchable:
        embedding_input_bytes(cve_id, text)
    return cve_id, len(text.encode("utf-8")), metadata_size


@dataclass(frozen=True)
class Dataset:
    manifest: dict[str, Any]
    manifest_path: Path
    manifest_sha256: str
    files: tuple[Path, ...]
    ids: frozenset[str]
    records: int
    file_bytes: int
    max_text_bytes: int
    max_metadata_bytes: int


def read_manifest(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"manifest not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid manifest JSON: {exc}") from exc
    if not isinstance(value, dict) or value.get("format") != "portable-cve-rag":
        raise ValueError("manifest format must be portable-cve-rag")
    if value.get("schema_version") != 2:
        raise ValueError(f"unsupported manifest schema version: {value.get('schema_version')!r}")
    if value.get("storage_format") != "json-array":
        raise ValueError("manifest storage_format must be json-array")
    if value.get("partitioning") != "cve-id-year":
        raise ValueError("manifest partitioning must be cve-id-year")
    return value


def read_json_array(path: Path) -> list[Any]:
    """Load one yearly file at a time using the standard JSON decoder."""
    try:
        with path.open("r", encoding="utf-8") as stream:
            records = json.load(stream)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path.name}: invalid JSON: {exc}") from exc
    except (OSError, UnicodeError) as exc:
        raise ValueError(f"cannot read {path.name}: {exc}") from exc
    if not isinstance(records, list):
        raise ValueError(f"{path.name}: top-level JSON must be an array")
    return records


def validate_dataset(manifest_path: Path) -> Dataset:
    manifest_path = manifest_path.expanduser().resolve()
    manifest = read_manifest(manifest_path)
    # Manifest file paths are repository-root-relative (for example,
    # data/CVE-2026.json).
    root = manifest_path.parent.parent
    entries = manifest.get("search_files")
    if not isinstance(entries, list) or not entries:
        raise ValueError("manifest.search_files must be a non-empty list")
    counts = manifest.get("counts")
    expected_total = counts.get("search") if isinstance(counts, dict) else None
    if not isinstance(expected_total, int) or expected_total < 1:
        raise ValueError("manifest.counts.search must be a positive integer")

    seen: set[str] = set()
    files: list[Path] = []
    total = 0
    total_bytes = 0
    max_text = 0
    max_metadata = 0
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("each search_files entry must be an object")
        path = safe_data_path(root, entry.get("path"))
        if path.suffix != ".json":
            raise ValueError(f"search file must end in .json: {path.name}")
        if not path.is_file():
            raise ValueError(f"search file not found: {path}")
        expected_size = entry.get("bytes")
        if not isinstance(expected_size, int) or path.stat().st_size != expected_size:
            raise ValueError(f"{path.name}: byte count does not match manifest")
        expected_hash = entry.get("sha256")
        actual_hash = sha256(path)
        if not isinstance(expected_hash, str) or actual_hash != expected_hash:
            raise ValueError(f"{path.name}: SHA-256 does not match manifest")
        expected_records = entry.get("record_count")
        if not isinstance(expected_records, int) or expected_records < 1:
            raise ValueError(f"{path.name}: invalid manifest record count")

        file_records = 0
        for record_number, record in enumerate(read_json_array(path), 1):
            cve_id, text_size, metadata_size = validate_record(
                record, f"{path.name}:record {record_number}", searchable=True
            )
            if cve_id in seen:
                raise ValueError(f"duplicate searchable ID: {cve_id}")
            seen.add(cve_id)
            file_records += 1
            max_text = max(max_text, text_size)
            max_metadata = max(max_metadata, metadata_size)
        if file_records != expected_records:
            raise ValueError(
                f"{path.name}: found {file_records:,} records; manifest says {expected_records:,}"
            )
        files.append(path)
        total += file_records
        total_bytes += expected_size

    if total != expected_total:
        raise ValueError(f"found {total:,} searchable records; manifest says {expected_total:,}")

    search_ids = frozenset(seen)
    rejected_entry = manifest.get("rejected_file")
    expected_rejected = counts.get("rejected") if isinstance(counts, dict) else None
    expected_all = counts.get("total") if isinstance(counts, dict) else None
    if not isinstance(rejected_entry, dict):
        raise ValueError("manifest.rejected_file must be an object")
    if not isinstance(expected_rejected, int) or expected_rejected < 1:
        raise ValueError("manifest.counts.rejected must be a positive integer")
    rejected_path = safe_data_path(root, rejected_entry.get("path"))
    if rejected_path.suffix != ".json" or not rejected_path.is_file():
        raise ValueError(f"rejected file is missing or not .json: {rejected_path}")
    rejected_size = rejected_entry.get("bytes")
    if not isinstance(rejected_size, int) or rejected_path.stat().st_size != rejected_size:
        raise ValueError("rejected file byte count does not match manifest")
    rejected_hash = rejected_entry.get("sha256")
    if not isinstance(rejected_hash, str) or sha256(rejected_path) != rejected_hash:
        raise ValueError("rejected file SHA-256 does not match manifest")
    rejected_manifest_count = rejected_entry.get("record_count")
    if rejected_manifest_count != expected_rejected:
        raise ValueError("rejected file count and manifest.counts.rejected disagree")
    rejected_count = 0
    for record_number, record in enumerate(read_json_array(rejected_path), 1):
        cve_id, text_size, metadata_size = validate_record(
            record, f"{rejected_path.name}:record {record_number}", searchable=False
        )
        if cve_id in seen:
            raise ValueError(f"duplicate ID across searchable and rejected data: {cve_id}")
        seen.add(cve_id)
        rejected_count += 1
        max_text = max(max_text, text_size)
        max_metadata = max(max_metadata, metadata_size)
    if rejected_count != expected_rejected:
        raise ValueError(
            f"found {rejected_count:,} rejected records; manifest says {expected_rejected:,}"
        )
    if expected_all != total + rejected_count or len(seen) != expected_all:
        raise ValueError("manifest.counts.total does not equal unique searchable plus rejected records")
    return Dataset(
        manifest=manifest,
        manifest_path=manifest_path,
        manifest_sha256=sha256(manifest_path),
        files=tuple(files),
        ids=search_ids,
        records=total,
        file_bytes=total_bytes + rejected_size,
        max_text_bytes=max_text,
        max_metadata_bytes=max_metadata,
    )


def iter_records(files: Sequence[Path]) -> Iterator[dict[str, Any]]:
    for path in files:
        yield from read_json_array(path)


def selected_records(
    records: Iterable[dict[str, Any]], start_after: str | None, limit: int | None
) -> Iterator[dict[str, Any]]:
    started = start_after is None
    emitted = 0
    for record in records:
        if not started:
            if record["id"] == start_after:
                started = True
            continue
        if limit is not None and emitted >= limit:
            return
        emitted += 1
        yield record
    if not started:
        raise ValueError(f"start ID was not encountered: {start_after}")


def embedding_batches(
    records: Iterable[dict[str, Any]], size: int
) -> Iterator[list[dict[str, Any]]]:
    """Keep both the input count and a conservative request token bound within limits."""
    if not 1 <= size <= MAX_EMBED_INPUTS:
        raise ValueError(f"embedding batch size must be between 1 and {MAX_EMBED_INPUTS:,}")
    batch: list[dict[str, Any]] = []
    total_bytes = 0
    for record in records:
        text_bytes = embedding_input_bytes(record["id"], record["text"])
        if batch and (len(batch) == size or total_bytes + text_bytes > MAX_EMBED_REQUEST_BYTES):
            yield batch
            batch = []
            total_bytes = 0
        batch.append(record)
        total_bytes += text_bytes
    if batch:
        yield batch


def retry(label: str, function: Callable[[], T], attempts: int) -> T:
    for attempt in range(1, attempts + 1):
        try:
            return function()
        except Exception as exc:
            status = getattr(exc, "status_code", None) or getattr(exc, "status", None)
            if isinstance(status, int) and 400 <= status < 500 and status not in {408, 409, 429}:
                raise RuntimeError(f"{label} rejected (HTTP {status}): {exc}") from exc
            if attempt == attempts:
                raise RuntimeError(f"{label} failed after {attempts} attempts: {exc}") from exc
            delay = min(2 ** (attempt - 1), 20)
            print(f"{label} failed ({exc}); retrying in {delay}s", file=sys.stderr)
            time.sleep(delay)
    raise AssertionError("unreachable")


def response_field(value: object, name: str) -> object | None:
    if isinstance(value, dict):
        return value.get(name)
    return getattr(value, name, None)


def vector_batches(
    vectors: Sequence[dict[str, Any]], max_bytes: int, namespace: str = ""
) -> Iterator[list[dict[str, Any]]]:
    """Measure the HTTP JSON bytes using Pinecone 9's required JSON encoder."""
    try:
        import orjson  # Installed by pinecone>=9; also used by its HTTP transport.
    except ImportError as exc:
        raise ValueError("install dependencies with: pip install -r requirements.txt") from exc
    if not 1 <= max_bytes <= MAX_UPSERT_BYTES:
        raise ValueError(f"upsert byte budget must be between 1 and {MAX_UPSERT_BYTES:,}")
    envelope: dict[str, Any] = {"vectors": []}
    if namespace:
        envelope["namespace"] = namespace
    base_size = len(orjson.dumps(envelope))
    batch: list[dict[str, Any]] = []
    size = base_size
    for vector in vectors:
        vector_size = len(orjson.dumps(vector))
        if base_size + vector_size > max_bytes:
            raise ValueError(f"{vector['id']}: one vector exceeds the configured upsert byte budget")
        if batch and (len(batch) == MAX_UPSERT_VECTORS or size + 1 + vector_size > max_bytes):
            yield batch
            batch = []
            size = base_size
        size += vector_size + (1 if batch else 0)
        batch.append(vector)
    if batch:
        yield batch


def checkpoint_contract(args: argparse.Namespace, dataset: Dataset) -> dict[str, Any]:
    return {
        "manifest_sha256": dataset.manifest_sha256,
        "index": args.index,
        "namespace": args.namespace,
        "model": args.model,
        "dimension": args.dimension,
    }


def read_checkpoint(path: Path, expected: dict[str, Any]) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"checkpoint not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid checkpoint JSON: {exc}") from exc
    if not isinstance(value, dict) or value.get("contract") != expected:
        raise ValueError("checkpoint does not match this manifest/index/namespace/embedding contract")
    if (
        not isinstance(value.get("last_id"), str)
        or type(value.get("uploaded")) is not int
        or value["uploaded"] <= 0
        or not isinstance(value.get("index_host"), str)
        or not value["index_host"]
    ):
        raise ValueError("checkpoint is missing last_id, uploaded, or index_host")
    return value


def write_checkpoint(
    path: Path, contract: dict[str, Any], index_host: str, last_id: str, uploaded: int
) -> None:
    path = path.expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    payload = {
        "contract": contract,
        "index_host": index_host,
        "last_id": last_id,
        "uploaded": uploaded,
    }
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def embed_batch(client: object, records: Sequence[dict[str, Any]], args: argparse.Namespace) -> list[list[float]]:
    validate_embedding_settings(args.model, args.dimension)
    if not 1 <= len(records) <= MAX_EMBED_INPUTS:
        raise ValueError(f"embedding request must contain 1 to {MAX_EMBED_INPUTS:,} inputs")
    if sum(embedding_input_bytes(record["id"], record["text"]) for record in records) > MAX_EMBED_REQUEST_BYTES:
        raise ValueError("embedding request exceeds the conservative 300,000-byte token budget")
    response = retry(
        "OpenAI embedding request",
        lambda: client.embeddings.create(  # type: ignore[attr-defined]
            model=args.model,
            input=[record["text"] for record in records],
            dimensions=args.dimension,
        ),
        args.retries,
    )
    rows = sorted(response.data, key=lambda row: row.index)  # type: ignore[attr-defined]
    if [row.index for row in rows] != list(range(len(records))):
        raise RuntimeError("OpenAI returned missing, duplicate, or unexpected embedding indices")
    result: list[list[float]] = []
    for record, row in zip(records, rows):
        values = [float(item) for item in row.embedding]
        if len(values) != args.dimension or not all(math.isfinite(item) for item in values):
            raise RuntimeError(f"{record['id']}: OpenAI returned an invalid embedding")
        result.append(values)
    return result


def upload(
    args: argparse.Namespace,
    dataset: Dataset,
    start_after: str | None,
    prior: int,
    expected_index_host: str | None,
) -> int:
    openai_key = os.getenv("OPENAI_API_KEY", "").strip()
    pinecone_key = os.getenv("PINECONE_API_KEY", "").strip()
    if not openai_key or not pinecone_key:
        raise ValueError("set OPENAI_API_KEY and PINECONE_API_KEY in .env or the environment")
    try:
        from openai import OpenAI
        from pinecone import Pinecone
    except ImportError as exc:
        raise ValueError("install dependencies with: pip install -r requirements.txt") from exc

    openai_client = OpenAI(api_key=openai_key)
    pc = Pinecone(api_key=pinecone_key)
    if not pc.indexes.exists(args.index):
        raise ValueError(f"Pinecone index does not exist: {args.index}")
    description = pc.indexes.describe(args.index)
    dimension = response_field(description, "dimension")
    metric = response_field(description, "metric")
    vector_type = response_field(description, "vector_type")
    integrated_embed = response_field(description, "embed")
    index_host = response_field(description, "host")
    status = response_field(description, "status")
    ready = response_field(status, "ready") if status is not None else None
    if (
        dimension != args.dimension
        or metric != "cosine"
        or vector_type not in {None, "dense"}
        or integrated_embed is not None
        or not isinstance(index_host, str)
        or not index_host
        or ready is not True
    ):
        raise ValueError(
            "index must be a ready client-embedded dense index with "
            f"dimension={args.dimension}, metric=cosine; got dimension={dimension}, "
            f"metric={metric}, vector_type={vector_type}, integrated_embed={integrated_embed is not None}, "
            f"ready={ready}"
        )
    if expected_index_host is not None and index_host != expected_index_host:
        raise ValueError(
            "checkpoint targets a different Pinecone index host; start a fresh upload "
            "instead of resuming"
        )
    index = pc.index(host=index_host)
    stats = retry("Pinecone namespace check", index.describe_index_stats, args.retries)
    namespaces = response_field(stats, "namespaces")
    if not isinstance(namespaces, Mapping):
        raise ValueError("could not verify the target namespace from Pinecone index statistics")
    summary = namespaces.get(args.namespace or "")
    if summary is not None:
        vector_count = response_field(summary, "vector_count")
        if type(vector_count) is not int or vector_count < 0:
            raise ValueError("Pinecone did not return a valid vector count for the target namespace")
        if vector_count and expected_index_host is None:
            raise ValueError(
                f"namespace {args.namespace or '<default>'!r} already contains {vector_count:,} vectors; "
                "choose a fresh --namespace for this snapshot, or use --resume with its matching "
                "checkpoint. Upserting into an older snapshot would leave removed CVEs searchable"
            )
    if expected_index_host is not None and start_after is not None:
        fetch_kwargs: dict[str, Any] = {"ids": [start_after]}
        if args.namespace:
            fetch_kwargs["namespace"] = args.namespace
        fetched = retry(
            "Pinecone checkpoint verification",
            lambda: index.fetch(**fetch_kwargs),
            args.retries,
        )
        vectors = response_field(fetched, "vectors")
        if not isinstance(vectors, Mapping) or start_after not in vectors:
            raise ValueError(
                f"checkpoint vector {start_after} is absent from the target index/namespace"
            )
    contract = checkpoint_contract(args, dataset)
    uploaded = 0
    source = selected_records(iter_records(dataset.files), start_after, args.limit)
    for records in embedding_batches(source, args.batch_size):
        embeddings = embed_batch(openai_client, records, args)
        vectors: list[dict[str, Any]] = []
        for record, values in zip(records, embeddings):
            metadata = dict(record["metadata"])
            metadata["text"] = record["text"]
            metadata["cve_id"] = record["id"]
            vectors.append({"id": record["id"], "values": values, "metadata": metadata})
        for batch in vector_batches(vectors, args.upsert_max_bytes, args.namespace):
            kwargs: dict[str, Any] = {"vectors": batch}
            if args.namespace:
                kwargs["namespace"] = args.namespace
            response = retry(
                "Pinecone upsert",
                lambda batch_kwargs=kwargs: index.upsert(**batch_kwargs),
                args.retries,
            )
            acknowledged = response_field(response, "upserted_count")
            if type(acknowledged) is not int or acknowledged != len(batch):
                raise RuntimeError(f"Pinecone acknowledged {acknowledged}/{len(batch)} vectors")
            uploaded += len(batch)
            write_checkpoint(
                args.checkpoint, contract, index_host, batch[-1]["id"], prior + uploaded
            )
        if uploaded == len(records) or uploaded % 1000 < len(records):
            print(f"Uploaded {uploaded:,} record(s); last ID {records[-1]['id']}", flush=True)
    return uploaded


def main() -> int:
    args = arguments()
    try:
        dataset = validate_dataset(args.manifest)
    except ValueError as exc:
        raise SystemExit(f"validation error: {exc}") from exc
    print(
        f"Validated {dataset.records:,} searchable records in {len(dataset.files)} yearly JSON file(s), "
        f"{dataset.file_bytes / (1024 * 1024):.1f} MiB total JSON data."
    )
    print(
        f"Largest text: {dataset.max_text_bytes:,} bytes; largest stored metadata: "
        f"{dataset.max_metadata_bytes:,}/{MAX_METADATA_BYTES:,} bytes."
    )
    print(
        "Embedding limits checked conservatively using UTF-8 bytes: "
        "8,192 per input and 300,000 per request."
    )

    if args.start_after and args.start_after not in dataset.ids:
        raise SystemExit(f"validation error: start ID is not in the searchable corpus: {args.start_after}")
    contract = checkpoint_contract(args, dataset)
    start_after = args.start_after
    prior = 0
    expected_index_host = None
    if args.resume:
        try:
            checkpoint = read_checkpoint(args.checkpoint.expanduser().resolve(), contract)
        except ValueError as exc:
            raise SystemExit(f"resume error: {exc}") from exc
        start_after = checkpoint["last_id"]
        prior = checkpoint["uploaded"]
        expected_index_host = checkpoint["index_host"]
        if start_after not in dataset.ids:
            raise SystemExit(f"resume error: checkpoint ID is not in this corpus: {start_after}")
        print(f"Resuming after {start_after} ({prior:,} previously uploaded).")

    if args.dry_run:
        print("Dry run complete: no API keys, embeddings, index calls, or uploads were used.")
        return 0

    try:
        count = upload(args, dataset, start_after, prior, expected_index_host)
    except (ValueError, RuntimeError) as exc:
        raise SystemExit(f"upload error: {exc}") from exc
    if count == 0:
        print("No records selected for upload.")
    else:
        print(f"Complete: uploaded {count:,} record(s) to {args.index}/{args.namespace or '<default>'}.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("Interrupted. Re-run with --resume to continue after the last successful batch.", file=sys.stderr)
        raise SystemExit(130)
