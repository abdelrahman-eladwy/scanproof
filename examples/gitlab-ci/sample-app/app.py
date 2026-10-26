"""Deliberately vulnerable demo code so Semgrep has something to report.

Never deploy this. It exists only to produce findings in the ScanProof demo project.
"""

import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # Command injection: user input flows into a shell command.
    return subprocess.check_output(f"ping -c 1 {host}", shell=True)


@app.route("/calc")
def calc():
    # Code injection: user input passed to eval.
    return str(eval(request.args.get("expr", "1+1")))
