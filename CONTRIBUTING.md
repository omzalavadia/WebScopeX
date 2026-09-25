# Contributing

Contributions are welcome for defensive and authorized reconnaissance use cases.

## Development

1. Create a Python 3.11+ virtual environment.
2. Install `requirements.txt` and `requirements-dev.txt`.
3. Keep scanner changes scope-aware and rate-limit friendly.
4. Add or update tests where practical.
5. Run `python -m py_compile webscopex.py` and `pytest` before opening a pull request.

Please avoid features whose primary purpose is persistence, credential theft, destructive exploitation, stealth/evasion, or unauthorized access.
