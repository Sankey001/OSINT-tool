"""TLS certificate inspection."""

import socket
import ssl
from datetime import datetime, timezone

from .. import net
from . import ModuleError, module


def _name(parts):
    return {k: v for rdn in parts for (k, v) in rdn}


def _date(value):
    return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)


def summarize(cert, version=None, cipher=None, verified=True, verify_error=None):
    not_before = _date(cert["notBefore"])
    not_after = _date(cert["notAfter"])
    now = datetime.now(timezone.utc)
    subject = _name(cert.get("subject", ()))
    issuer = _name(cert.get("issuer", ()))
    san = [v for (k, v) in cert.get("subjectAltName", ()) if k == "DNS"]
    return {
        "subject": subject.get("commonName"),
        "organization": subject.get("organizationName"),
        "issuer": issuer.get("organizationName") or issuer.get("commonName"),
        "issuer_cn": issuer.get("commonName"),
        "valid_from": not_before.isoformat(),
        "valid_to": not_after.isoformat(),
        "days_left": (not_after - now).days,
        "expired": now > not_after,
        "san": san,
        "serial": cert.get("serialNumber"),
        "tls_version": version,
        "cipher": cipher[0] if cipher else None,
        "verified": verified,
        "verify_error": verify_error,
    }


def _handshake(domain, verify):
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((domain, 443), timeout=8) as sock:
        with ctx.wrap_socket(sock, server_hostname=domain) as tls:
            if verify:
                return tls.getpeercert(), tls.version(), tls.cipher()
            der = tls.getpeercert(binary_form=True)
            return _decode_der(der), tls.version(), tls.cipher()


def _decode_der(der):
    # The stdlib can only parse PEM files into dicts; round-trip through a temp file.
    import os
    import tempfile

    pem = ssl.DER_cert_to_PEM_cert(der)
    fd, path = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(pem)
        return ssl._ssl._test_decode_cert(path)  # noqa: SLF001 - no public API for this
    finally:
        os.unlink(path)


@module("tls", "TLS Certificate", ["domain"],
        "Issuer, validity window, SANs and negotiated protocol on port 443.", order=35)
def tls(domain):
    if not net.host_is_public(domain):
        raise ModuleError("Refusing to probe a private/internal address")
    try:
        cert, version, cipher = _handshake(domain, verify=True)
        return summarize(cert, version, cipher)
    except ssl.SSLCertVerificationError as exc:
        reason = exc.verify_message or str(exc)
        try:
            cert, version, cipher = _handshake(domain, verify=False)
        except Exception:
            raise ModuleError(f"Certificate verification failed: {reason}")
        return summarize(cert, version, cipher, verified=False, verify_error=reason)
    except (OSError, ssl.SSLError) as exc:
        raise ModuleError(f"TLS handshake failed: {exc}")
