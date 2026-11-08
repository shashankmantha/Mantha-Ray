# Troubleshooting

## A script says "Permission denied"

```bash
chmod +x mantha-ray.sh scripts/*.sh
```

## Docker permission denied or unavailable

```bash
sudo systemctl enable --now docker
docker info
sudo usermod -aG docker "$USER"   # then log out and back in
```

Don't work around it with `sudo`: the application and its results should stay owned by your account.

## Missing virtual environment or web interface

```bash
./scripts/setup.sh                    # recreates .venv
./scripts/setup.sh --build-frontend   # if src/static_triage/web_dist/index.html is missing (needs Node.js)
```

## "--progress-jsonl is not recognized", or a new feature is missing in scans

The analysis image is older than the code. Rebuild it:

```bash
./scripts/setup.sh
```

After a `git pull` that changes anything under `src/`, always run `setup.sh` again; the image holds its own copy of the scanner.

## Every file shows ClamAV as failed

The image's signatures are more than 7 days old. Run `./scripts/setup.sh` while online; it refreshes only the signatures.

If ClamAV still fails, look at its saved output:

```bash
cat ~/mantha-ray-results/<case-id>/raw/clamav/stderr.txt
```

## YARA-X shows "No rule packs installed"

```bash
mantha-ray packs update
```

If that fails:

- **"couldn't reach GitHub":** the host has no internet access. Install a bundle you copied over instead, with `packs install FILE.tar.gz`, keeping its `.minisig` next to it.
- **"signature check failed":** the bundle was changed after it was signed, or it was signed with a different key. Nothing was installed. Get the bundle again from the releases page.
- **"older than … already installed":** rollback protection. Use `packs rollback` if you meant to go back.

## The source and results folders overlap

Choose two separate locations, for example `~/samples/suspicious-folder` and `~/mantha-ray-results`. Neither can be inside the other, and neither can contain the rule pack folder.

## A scan takes a long time, or many files are "not reached"

- **Programs are scanned smallest first**, so the files not reached are the largest ones. Large programs are the slowest part of capa and FLOSS.
- **Use the High profile, or Custom with longer budgets,** for big game or application folders.
- **The Queue view** shows which file is running and which are waiting.
- **To stop and keep what's finished,** use **Stop scan…** (or `./scripts/stop-scan.sh`); a report is still saved.

## A clean file shows low risk

A capa capability such as "terminate process" is informational. Low risk means a weak behaviour was seen, not that the file is malicious.

## Running the tests by hand

From the repository root:

```bash
./scripts/test.sh
PYTHONPATH="$PWD/src" python3 -m unittest discover -s tests -p 'test_*.py' -v
```

To run the YARA-X tests against the real scanner, point `MANTHA_RAY_YR` at a `yr` binary.
