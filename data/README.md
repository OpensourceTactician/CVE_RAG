# Readable CVE records

Grouped by the year in each CVE ID, not its publication date. The **November 9, 2026 incremental update adds 3,322 newly published CVEs**, with publication dates after **2026-11-02T13:54:38Z** through **2026-11-09T13:57:43Z**. Existing records and the rejected file are unchanged.

This is a mixed snapshot: a July 13 base, September 9 refresh of 2026 records, and subsequent incremental additions. Existing records retain their previous source dates. New publications can have older CVE ID years and are added to the corresponding year file. Per-record source dates and the manifest distinguish those cohorts.

New records use CVE commit `d52b78cbe051eaba88a7c0975de4a3cc3c0eb96b`, NVD source snapshots through `2026-11-09T13:57:43Z`, EPSS scores from `2026-11-09T12:00:23Z`, and KEV catalog `2026.11.06`. Weekly updates append newly published records only; existing records are not refreshed or revalidated against current source statuses.

These are the canonical, indented JSON arrays of `id`, `text`, and `metadata` record objects. IDs are unique and sorted numerically. The uploader reads these same files and excludes `rejected.json`. [`manifest.json`](manifest.json) records file counts/checksums, original snapshot provenance, each publication window, and the next incremental cutoff.

Records are bounded summaries; `text_truncated` and `*_overflow_count` identify omissions, with source links for the complete record. Missing optional enrichment means unavailable or unassessed. Solution/workaround guidance does not prove a working fix exists. New NVD product labels retain their conditional applicability scope.

Run `python upload_to_pinecone.py --dry-run` from the repository root to validate the corpus without API calls. See the [main README](../README.md) for Git LFS and upload instructions.

| File | Records | Newly added |
| --- | ---: | ---: |
| [CVE-1999.json](CVE-1999.json) | 1,540 | 0 |
| [CVE-2000.json](CVE-2000.json) | 1,236 | 0 |
| [CVE-2001.json](CVE-2001.json) | 1,537 | 0 |
| [CVE-2002.json](CVE-2002.json) | 2,357 | 0 |
| [CVE-2003.json](CVE-2003.json) | 1,504 | 0 |
| [CVE-2004.json](CVE-2004.json) | 2,644 | 0 |
| [CVE-2005.json](CVE-2005.json) | 4,627 | 0 |
| [CVE-2006.json](CVE-2006.json) | 6,995 | 0 |
| [CVE-2007.json](CVE-2007.json) | 6,458 | 0 |
| [CVE-2008.json](CVE-2008.json) | 7,005 | 0 |
| [CVE-2009.json](CVE-2009.json) | 4,921 | 0 |
| [CVE-2010.json](CVE-2010.json) | 5,075 | 0 |
| [CVE-2011.json](CVE-2011.json) | 4,646 | 0 |
| [CVE-2012.json](CVE-2012.json) | 5,492 | 0 |
| [CVE-2013.json](CVE-2013.json) | 6,226 | 0 |
| [CVE-2014.json](CVE-2014.json) | 8,436 | 0 |
| [CVE-2015.json](CVE-2015.json) | 8,118 | 0 |
| [CVE-2016.json](CVE-2016.json) | 9,374 | 0 |
| [CVE-2017.json](CVE-2017.json) | 14,768 | 0 |
| [CVE-2018.json](CVE-2018.json) | 16,190 | 0 |
| [CVE-2019.json](CVE-2019.json) | 16,099 | 1 |
| [CVE-2020.json](CVE-2020.json) | 19,398 | 1 |
| [CVE-2021.json](CVE-2021.json) | 22,598 | 0 |
| [CVE-2022.json](CVE-2022.json) | 26,438 | 2 |
| [CVE-2023.json](CVE-2023.json) | 30,651 | 0 |
| [CVE-2024.json](CVE-2024.json) | 38,438 | 2 |
| [CVE-2025.json](CVE-2025.json) | 43,395 | 28 |
| [CVE-2026.json](CVE-2026.json) | 85,707 | 3,288 |
| [rejected.json](rejected.json) | 868 | 0 |

**Total:** 401,873 searchable records plus 868 rejected records kept separately.
