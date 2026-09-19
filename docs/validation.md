# GRIM Validation

Results from validating GRIM against real world audit material. Identifying details of the source material have been removed.

## What was tested

- A compromised web application: upload handling accepted an attacker controlled file type allowlist, leading to remote code execution and persistence.
- A clean baseline used to measure false positives.

## Results

### Exposure scan

- Single pass over a multi gigabyte backup archive.
- Detected every artifact that manual analysis found, including web executable webshell drop ins, a downloader and stager, and native executable payloads in web served directories.
- Completed on a phone running Termux, single thread.

### Drift scan

- Diffing a known good baseline against a later snapshot isolated the added stager, executables, and newly modified web executable files.
- Wrapper root normalization aligned timestamped backup roots automatically.

### Code scan

- Flagged the root cause (attacker controlled upload type validation) as **critical**, the finding that closes the whole incident class.

## What this shows

1. **Detection gap closed for this incident class.** File policy and heuristic scanning catch what signature only engines miss.
2. **Drift detection is high signal.** Added executables in web paths surface in one scan of a new backup.
3. **Fast enough for practical use** on large archives and low resource devices.
4. **AI usable output.** Every finding carries a location, evidence, confidence, and a fix.

## Reproduce

```bash
PYTHONPATH=src python3 -m grim tool audit_exposure --path backup.tar.gz --format md
PYTHONPATH=src python3 -m grim diff baseline.tar.gz current.tar.gz --format md
PYTHONPATH=src python3 -m grim scan /path/to/app-source --no-network
python3 tests/run_all.py
```
