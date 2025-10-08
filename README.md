# 403 Bypass Scanner (GUI)

A Tkinter-based tool for security testing to probe potential 403 bypass behaviors across various path/header/method mutations.

Important: Use only on systems and targets you have explicit authorization to test. Unauthorized use may be illegal.

## Features

- Path mangling variants (encodings, traversal, mixed separators)
- Header variations (X-Original-URL, X-Rewrite-URL, forwarding hints, content negotiation)
- Multiple methods (GET/HEAD/OPTIONS and optional POST/PUT/DELETE/PATCH)
- Concurrency with configurable threads and pacing
- Proxy, cookies, user-agent support
- Export results to CSV/JSON and filter by status

## Install

1. Ensure Python 3.10+.
2. Create a venv and install deps:

```bash
python -m venv .venv
. .venv/Scripts/activate
pip install -r requirements.txt
```

## Run

```bash
python -m app.gui
```

## Notes

- Tool sends requests without following redirects to preserve status codes.
- Consider using a proxy like Burp/ZAP via the Proxy field for inspection.
- Always coordinate testing windows and rate limits with the asset owner.
