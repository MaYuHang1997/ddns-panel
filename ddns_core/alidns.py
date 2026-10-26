"""
AliDNS OpenAPI client - ZERO third-party dependencies.

Uses only the Python standard library (urllib, hmac, hashlib) so it can run
on any machine with Python 3.8+, no pip install required.

Two signature versions are implemented:
  - V2 (classic): HMAC-SHA1 over the canonicalized query string
  - V3 (new):     ACS3-HMAC-SHA256 with x-acs-* headers

All outbound requests explicitly bypass any system/HTTP proxy, because a
proxy would make Aliyun observe the proxy's egress IP instead of ours.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from typing import Any

# Service endpoints for Alidns (2015-01-09)
ENDPOINT_PUBLIC = "https://alidns.aliyuncs.com/"
ENDPOINT_CN_HANGZHOU = "https://alidns.cn-hangzhou.aliyuncs.com/"

API_VERSION = "2015-01-09"

# Aliyun wants RFC3986 encoding, which urllib's quote_via=quote with safe='~'
# matches closely enough, plus space must be %20 not '+'.
_NO_PROXY_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _rfc3986(
    value: Any,
    safe: str = "~",
    encoding: str | None = None,
    errors: str | None = None,
) -> str:
    """RFC3986 percent-encoding.

    Signature compatible with ``urllib.parse.quote`` so it can be passed as
    ``quote_via`` to ``urlencode`` (which calls it with 4 positional args).
    """
    text = "" if value is None else str(value)
    return urllib.parse.quote(
        text, safe=safe, encoding=encoding or "utf-8", errors=errors or "strict"
    ).replace("+", "%20")


class AliDnsError(RuntimeError):
    """Aliyun returned an error payload or a non-200 response."""

    def __init__(
        self,
        code: str,
        message: str,
        request_id: str = "",
        status: int = 0,
        body: str = "",
    ) -> None:
        self.code = code
        self.message = message
        self.request_id = request_id
        self.status = status
        self.body = body
        super().__init__(f"[{code}] {message} (requestId={request_id}, http={status})")


class AliDnsClient:
    """Minimal Alidns API client.

    Attributes:
        access_key_id: RAM AccessKey ID.
        access_key_secret: RAM AccessKey secret.
        endpoint: Service endpoint URL.
    """

    def __init__(
        self,
        access_key_id: str,
        access_key_secret: str,
        endpoint: str = ENDPOINT_PUBLIC,
        timeout: float = 15.0,
    ) -> None:
        self.access_key_id = access_key_id
        self.access_key_secret = access_key_secret
        self.endpoint = endpoint
        self.timeout = timeout

    # ------------------------------------------------------------------
    # Signature V2 (HMAC-SHA1 / query-string parameters)
    # ------------------------------------------------------------------
    def _sign_v2(self, params: dict[str, Any]) -> str:
        canonical = "&".join(
            f"{_rfc3986(k)}={_rfc3986(params[k])}" for k in sorted(params)
        )
        string_to_sign = f"GET&{_rfc3986('/')}&{_rfc3986(canonical)}"
        digest = hmac.new(
            f"{self.access_key_secret}&".encode("utf-8"),
            string_to_sign.encode("utf-8"),
            hashlib.sha1,
        ).digest()
        return base64.b64encode(digest).decode("utf-8")

    def call_v2(self, action: str, **params: Any) -> dict[str, Any]:
        base: dict[str, Any] = {
            "Format": "JSON",
            "Version": API_VERSION,
            "AccessKeyId": self.access_key_id,
            "SignatureMethod": "HMAC-SHA1",
            "Timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "SignatureVersion": "1.0",
            "SignatureNonce": str(uuid.uuid4()),
            "Action": action,
        }
        base.update({k: v for k, v in params.items() if v is not None})
        base["Signature"] = self._sign_v2(base)
        url = f"{self.endpoint}?{urllib.parse.urlencode(base, quote_via=_rfc3986)}"
        return self._request(url, method="GET")

    # ------------------------------------------------------------------
    # Signature V3 (ACS3-HMAC-SHA256 / body parameters)
    # ------------------------------------------------------------------
    def _sign_v3(
        self,
        query: dict[str, Any],
        headers: dict[str, str],
        body: str,
    ) -> tuple[str, str]:
        """Return ``(signature, signed_headers)``.

        ``signed_headers`` is the exact ``;``-joined lowercase header list that
        went into the canonical request, and must be reused verbatim in the
        Authorization header or the gateway will reject the request.
        """
        canonical_query = "&".join(
            f"{_rfc3986(k)}={_rfc3986(query[k])}" for k in sorted(query)
        )
        signed = sorted(
            {h.lower() for h in headers}
            | {
                "x-acs-action",
                "x-acs-content-sha256",
                "x-acs-date",
                "x-acs-signature-nonce",
                "x-acs-version",
            }
        )
        canonical_headers = "".join(f"{h}:{headers.get(h, '').strip()}\n" for h in signed)
        hashed_payload = hashlib.sha256(body.encode("utf-8")).hexdigest()
        canonical_request = "\n".join(
            ["POST", "/", canonical_query, canonical_headers, ";".join(signed), hashed_payload]
        )
        string_to_sign = (
            "ACS3-HMAC-SHA256\n"
            + hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()
        )
        signature = hmac.new(
            self.access_key_secret.encode("utf-8"),
            string_to_sign.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return signature, ";".join(signed)

    def call_v3(self, action: str, **params: Any) -> dict[str, Any]:
        query: dict[str, Any] = {}
        body = urllib.parse.urlencode(
            {k: v for k, v in params.items() if v is not None}, quote_via=_rfc3986
        )
        host = urllib.parse.urlparse(self.endpoint).netloc
        headers = {
            "host": host,
            "content-type": "application/x-www-form-urlencoded",
            "accept": "application/json",
            "x-acs-action": action,
            "x-acs-version": API_VERSION,
            "x-acs-date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "x-acs-signature-nonce": str(uuid.uuid4()),
            "x-acs-content-sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
        }
        signature, signed_headers = self._sign_v3(query, headers, body)
        headers["Authorization"] = (
            f"ACS3-HMAC-SHA256 Credential={self.access_key_id},"
            f"SignedHeaders={signed_headers},"
            f"Signature={signature}"
        )
        return self._request(self.endpoint, method="POST", body=body, headers=headers)

    # ------------------------------------------------------------------
    def _request(
        self,
        url: str,
        method: str = "GET",
        body: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        data = body.encode("utf-8") if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            with _NO_PROXY_OPENER.open(req, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace")
            try:
                payload = json.loads(raw)
            except Exception:  # noqa: BLE001
                raise AliDnsError(
                    "HttpError", f"HTTP {exc.code}: {raw[:200]}", status=exc.code
                ) from exc
            raise AliDnsError(
                payload.get("Code", "Unknown"),
                payload.get("Message", ""),
                payload.get("RequestId", ""),
                exc.code,
                raw,
            ) from exc
        except Exception as exc:  # noqa: BLE001
            raise AliDnsError("NetworkError", str(exc)) from exc

        try:
            payload = json.loads(raw)
        except Exception as exc:  # noqa: BLE001
            raise AliDnsError("InvalidJson", raw[:200], body=raw) from exc

        # Aliyun signals application errors with a Code/Message pair
        if isinstance(payload, dict) and payload.get("Code"):
            raise AliDnsError(
                payload.get("Code", "Unknown"),
                payload.get("Message", ""),
                payload.get("RequestId", ""),
                200,
                raw,
            )
        return payload

    # ------------------------------------------------------------------
    # DDNS-relevant actions
    # ------------------------------------------------------------------
    def list_domains(self, page: int = 1, size: int = 100) -> dict[str, Any]:
        """List all domains under this account."""
        return self.call_v2("DescribeDomains", PageNumber=page, PageSize=size)

    def list_records(
        self, domain: str, page: int = 1, size: int = 500
    ) -> dict[str, Any]:
        """List every record of one domain."""
        return self.call_v2(
            "DescribeDomainRecords", DomainName=domain, PageNumber=page, PageSize=size
        )

    def describe_subdomain(
        self, subdomain: str, rtype: str | None = None
    ) -> dict[str, Any]:
        """Look up a specific subdomain (e.g. home.example.com)."""
        return self.call_v2("DescribeSubDomainRecords", SubDomain=subdomain, Type=rtype)

    def record_info(self, record_id: str) -> dict[str, Any]:
        """Read the current state of one record by RecordId."""
        return self.call_v2("DescribeDomainRecordInfo", RecordId=record_id)

    def update_record(
        self, record_id: str, rr: str, rtype: str, value: str, ttl: int = 600
    ) -> dict[str, Any]:
        """Point an existing record at a new value."""
        return self.call_v2(
            "UpdateDomainRecord",
            RecordId=record_id,
            RR=rr,
            Type=rtype,
            Value=value,
            TTL=ttl,
        )

    def add_record(
        self, domain: str, rr: str, rtype: str, value: str, ttl: int = 600
    ) -> dict[str, Any]:
        """Create a new record and return its RecordId."""
        return self.call_v2(
            "AddDomainRecord",
            DomainName=domain,
            RR=rr,
            Type=rtype,
            Value=value,
            TTL=ttl,
        )

    def delete_record(self, record_id: str) -> dict[str, Any]:
        """Delete a record by RecordId."""
        return self.call_v2("DeleteDomainRecord", RecordId=record_id)
