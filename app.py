import os
import re
import uuid
from functools import wraps

import msal
from dotenv import load_dotenv
from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from checker import check_domain, check_ip

# ---------------------------------------------------------------------------
# Load config: .env first, then override sensitive values from Azure Key Vault
# ---------------------------------------------------------------------------
load_dotenv()

_KEY_VAULT_URI = os.getenv("KEY_VAULT_URI", "").strip()
if _KEY_VAULT_URI:
    try:
        from azure.identity import DefaultAzureCredential
        from azure.keyvault.secrets import SecretClient

        _kv = SecretClient(vault_url=_KEY_VAULT_URI, credential=DefaultAzureCredential())

        # Only true secrets are stored in Key Vault.
        # Non-sensitive IDs come from App Service environment variables (or local .env).
        _SECRET_MAP = {
            "azureclientsecret": "AZURE_CLIENT_SECRET",
            "flasksecretkey":    "FLASK_SECRET_KEY",
            "abuseipdb-api-key": "ABUSEIPDB_API_KEY",
            "virustotal-api-key": "VIRUSTOTAL_API_KEY",
        }
        for kv_name, env_name in _SECRET_MAP.items():
            try:
                os.environ[env_name] = _kv.get_secret(kv_name).value
            except Exception:
                pass  # Secret may not exist; fall back to env var
    except Exception as _kv_err:
        import warnings
        warnings.warn(f"Key Vault load failed: {_kv_err}")

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", os.urandom(24))

# ---------------------------------------------------------------------------
# Microsoft Entra (Azure AD) configuration
# ---------------------------------------------------------------------------
CLIENT_ID = os.getenv("AZURE_CLIENT_ID")
CLIENT_SECRET = os.getenv("AZURE_CLIENT_SECRET")
TENANT_ID = os.getenv("AZURE_TENANT_ID")
AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
REDIRECT_PATH = "/getAToken"
REDIRECT_URI = os.getenv("REDIRECT_URI", "http://localhost:5000/getAToken")
SCOPE = ["User.Read"]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
IP_PATTERN = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
IPV6_PATTERN = re.compile(r"^[0-9a-fA-F:]+$")
DOMAIN_PATTERN = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


def _config_missing() -> str | None:
    """Return an error message if any required env var is unset."""
    missing = [v for v in ("AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_TENANT_ID") if not os.getenv(v)]
    if missing:
        return (
            f"Missing environment variables: {', '.join(missing)}. "
            "Copy .env.example to .env and fill in your Azure App Registration credentials, "
            "then restart the server."
        )
    return None


def _build_msal_app(cache=None):
    return msal.ConfidentialClientApplication(
        CLIENT_ID,
        authority=AUTHORITY,
        client_credential=CLIENT_SECRET,
        token_cache=cache,
    )


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def _validate_target(target: str) -> tuple[bool, str]:
    """Return (is_valid, type) where type is 'ip' or 'domain'."""
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
@login_required
def index():
    return render_template("index.html", user=session["user"])


@app.route("/login")
def login():
    if session.get("user"):
        return redirect(url_for("index"))

    err = _config_missing()
    if err:
        return render_template("login.html", error=err)

    try:
        flow = _build_msal_app().initiate_auth_code_flow(
            SCOPE,
            redirect_uri=REDIRECT_URI,
        )
    except Exception as exc:
        return render_template("login.html", error=str(exc))

    session["flow"] = flow
    return redirect(flow["auth_uri"])


@app.route(REDIRECT_PATH)
def authorized():
    try:
        cache = msal.SerializableTokenCache()
        result = _build_msal_app(cache).acquire_token_by_auth_code_flow(
            session.pop("flow", {}),
            request.args,
        )
        if "error" in result:
            return render_template(
                "login.html",
                error=result.get("error_description", result["error"]),
            )
        session["user"] = result.get("id_token_claims")
        if cache.has_state_changed:
            session["token_cache"] = cache.serialize()
    except Exception as exc:
        return render_template("login.html", error=str(exc))

    return redirect(url_for("index"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        AUTHORITY
        + "/oauth2/v2.0/logout"
        + "?post_logout_redirect_uri="
        + url_for("login", _external=True)
    )


@app.route("/check", methods=["POST"])
@login_required
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

    return render_template(
        "index.html",
        user=session["user"],
        results=results,
        target=target,
    )


if __name__ == "__main__":
    app.run(debug=os.getenv("FLASK_ENV") == "development")
