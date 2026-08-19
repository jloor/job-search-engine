"""Job-search engine: board scanner, fit triage, and a mail relay with an approval gate.

🚨 WHY THIS FILE TOUCHES sys.path. The modules here import each other by BARE name
(`import gitsync`, `import candidate`, `import gates`), which worked when they sat in one
flat directory on the container's WORKDIR. Installed as a package they live inside
site-packages/job_search_engine/, and that directory is not itself on sys.path, so every
bare import fails.

⚠️ IT FAILED IN THE WORST WAY: the service still answered /health, because the failure only
surfaced when a scheduled job ran. "ModuleNotFoundError: No module named 'gitsync'" appeared
in job output while the container looked healthy.

The alternative was rewriting every intra-module import to `from job_search_engine import x`.
That is more conventional, but the test suite deliberately loads app.py BY PATH so it can run
from a clean clone with nothing installed, and package-qualified imports break that. One
documented line here keeps both callers working.
"""
import pathlib
import sys

_HERE = str(pathlib.Path(__file__).resolve().parent)
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

# 🚨 THE ONLY COPY OF THIS NUMBER. app.py reads it out of this file rather than declaring
# its own, and /health serves it to an authenticated caller. A second literal anywhere is
# the bug that made a container report 0.4.0 and send someone to debug the wrong code.
__version__ = "0.18.0"
