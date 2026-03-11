import os
import re

from dotenv import load_dotenv
from flask import Flask, flash, redirect, render_template, request, url_for

from checker import check_domain, check_ip

load_dotenv()

app = Flask(__name__)
app.secret_key = os.urandom(24)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
IP_PATTERN = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
DOMAIN_PATTERN = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


def _validate_target(target: str) -> tuple[bool, str]:
    target = target.strip()
    if IP_PATTERN.match(target):
        parts = target.split(".")
        if all(0 <= int(p) <= 255 for p in parts):
            return True, "ip"
        return False, ""
    if DOMAIN_PATTERN.match(target):
        return True, "domain"
    return False, ""


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/check", methods=["POST"])
def check():
    target = request.form.get("target", "").strip()

    if not target:
        flash("Please enter an IP address or domain name.", "warning")
        return redirect(url_for("index"))

    valid, kind = _validate_target(target)
    if not valid:
        flash(
            "Invalid input. Please enter a valid IPv4 address or domain name.",
            "danger",
        )
        return redirect(url_for("index"))

    if kind == "ip":
        results = check_ip(target)
    else:
        results = check_domain(target)

    return render_template("index.html", results=results, target=target)


if __name__ == "__main__":
    app.run(debug=os.getenv("FLASK_ENV") == "development")
