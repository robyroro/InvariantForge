"""Small app for an InvariantForge walkthrough. Not imported by the scanner."""

import subprocess
import sys


def echo(message: str) -> None:
    subprocess.run([sys.executable, "-c", "import sys; print(sys.argv[1])", message], check=True)
