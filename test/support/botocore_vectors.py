#!/usr/bin/env python3
# /// script
# dependencies = ["botocore==1.42.78"]
# ///
"""Generate test/fixtures/sigv4_vectors.json using botocore's SigV4 signers."""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from urllib.parse import parse_qs, parse_qsl, urlsplit, urlunsplit

import botocore
from botocore.auth import (
    S3ExpressAuth,
    S3ExpressQueryAuth,
    S3SigV4Auth,
    S3SigV4QueryAuth,
    SigV4Auth,
)
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials

EXPECTED_BOTOCORE_VERSION = "1.42.78"
ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
FIXTURE = ROOT / "test" / "fixtures" / "sigv4_vectors.json"

ACCESS_KEY = "AKIDEXAMPLE"
SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
REGION = "us-east-1"
TIMESTAMP = "20250101T000000Z"
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def make_signer(
    kind: str,
    service: str,
    expires: int | None = None,
    session_token: str | None = None,
    secret_access_key: str = SECRET_KEY,
):
    creds = Credentials(ACCESS_KEY, secret_access_key, session_token)
    if kind == "s3":
        return S3SigV4Auth(creds, service, REGION)
    if kind == "s3_query":
        return S3SigV4QueryAuth(creds, service, REGION, expires=expires or 900)
    if kind == "s3express":
        return S3ExpressAuth(creds, service, REGION, identity_cache=None)
    if kind == "s3express_query":
        return S3ExpressQueryAuth(
            creds, service, REGION, identity_cache=None, expires=expires or 900
        )
    if kind == "sigv4":
        return SigV4Auth(creds, service, REGION)
    raise ValueError(f"Unknown signer kind: {kind}")


def sign_request(
    *,
    id: str,
    kind: str,
    signer_type: str,
    method: str,
    url: str,
    service: str,
    headers: dict[str, str] | None = None,
    body: str = "",
    expires_in: int | None = None,
    session_token: str | None = None,
    s3express_session: bool = False,
    secret_access_key: str = SECRET_KEY,
    timestamp: str = TIMESTAMP,
    apply_checksum_header: bool = True,
    source: str | None = None,
    query_via_params: bool = False,
) -> dict:
    auth = make_signer(
        signer_type,
        service,
        expires=expires_in,
        session_token=session_token,
        secret_access_key=secret_access_key,
    )
    req_url = url
    req_params = None
    if query_via_params:
        parts = urlsplit(url)
        req_url = urlunsplit((parts.scheme, parts.netloc, parts.path, "", parts.fragment))
        req_params = dict(parse_qsl(parts.query, keep_blank_values=True))

    req = AWSRequest(
        method=method,
        url=req_url,
        params=req_params,
        headers=dict(headers or {}),
        data=body.encode("utf-8"),
    )
    req.context["timestamp"] = timestamp
    auth._modify_request_before_signing(req)
    canonical_request = auth.canonical_request(req)
    string_to_sign = auth.string_to_sign(req, canonical_request)
    signature = auth.signature(string_to_sign, req)
    auth._inject_signature_to_request(req, signature)

    result = {
        "id": id,
        "kind": kind,
        "method": method,
        "url": url,
        "service": service,
        "headers": headers or {},
        "body": body,
        "canonical_request": canonical_request,
        "string_to_sign": string_to_sign,
        "signature": signature,
    }
    if source is not None:
        result["source"] = source
    if secret_access_key != SECRET_KEY:
        result["secret_access_key"] = secret_access_key
    if timestamp != TIMESTAMP:
        result["timestamp"] = timestamp
    if not apply_checksum_header:
        result["apply_checksum_header"] = False
    if session_token is not None:
        result["session_token"] = session_token
    if s3express_session:
        result["s3express_session"] = True
    if expires_in is not None:
        result["expires_in"] = expires_in
        result["signed_url"] = req.url
        parsed_sig = parse_qs(urlsplit(req.url).query)["X-Amz-Signature"][0]
        assert parsed_sig == signature
    else:
        result["authorization"] = req.headers["Authorization"]
    return result


def canonical_lines(
    signer_type: str,
    service: str,
    method: str,
    url: str,
    headers: dict[str, str] | list[tuple[str, str]] | None = None,
) -> list[str]:
    auth = make_signer(signer_type, service)
    req = AWSRequest(method=method, url=url, headers={}, data=b"")
    if isinstance(headers, list):
        for k, v in headers:
            req.headers.add_header(k, v)
    elif headers:
        for k, v in headers.items():
            req.headers[k] = v
    req.context["timestamp"] = TIMESTAMP
    auth._modify_request_before_signing(req)
    return auth.canonical_request(req).split("\n")


def build_vectors() -> dict:
    vectors = [
        sign_request(
            id="s3_space",
            kind="header",
            signer_type="s3",
            method="GET",
            url="https://examplebucket.s3.us-east-1.amazonaws.com/a%20b.txt",
            service="s3",
        ),
        sign_request(
            id="api_space",
            kind="header",
            signer_type="sigv4",
            method="GET",
            url="https://x.execute-api.us-east-1.amazonaws.com/a%20b",
            service="execute-api",
            headers={"x-amz-content-sha256": EMPTY_SHA256},
        ),
        sign_request(
            id="s3_outposts_space",
            kind="header",
            signer_type="s3",
            method="GET",
            url="https://myaccesspoint-123456789012.op-0123456789abcdef0.s3-outposts.us-east-1.amazonaws.com/a%20b.txt",
            service="s3-outposts",
        ),
        sign_request(
            id="iot_tunneling",
            kind="header",
            signer_type="sigv4",
            method="GET",
            url="https://api.tunneling.iot.us-east-1.amazonaws.com/",
            service="IoTSecuredTunneling",
            headers={"x-amz-content-sha256": EMPTY_SHA256},
        ),
        sign_request(
            id="meta_sort",
            kind="header",
            signer_type="s3",
            method="PUT",
            url="https://examplebucket.s3.us-east-1.amazonaws.com/k",
            service="s3",
            headers={"x-amz-meta-a": "1", "x-amz-meta-a-b": "2"},
            body="hello",
        ),
        sign_request(
            id="port",
            kind="header",
            signer_type="s3",
            method="GET",
            url="http://localhost:4566/bucket/key",
            service="s3",
        ),
        sign_request(
            id="presign_port",
            kind="presign",
            signer_type="s3_query",
            method="GET",
            url="http://localhost:4566/bucket/key",
            service="s3",
            expires_in=900,
        ),
        sign_request(
            id="presign_query_plus",
            kind="presign",
            signer_type="s3_query",
            method="GET",
            url="https://examplebucket.s3.us-east-1.amazonaws.com/key?x=a+b",
            service="s3",
            expires_in=900,
        ),
        sign_request(
            id="presign_query_tilde_lower",
            kind="presign",
            signer_type="s3_query",
            method="GET",
            url="https://examplebucket.s3.us-east-1.amazonaws.com/key?x=%7e",
            service="s3",
            expires_in=900,
        ),
        sign_request(
            id="presign_query_hex_lower",
            kind="presign",
            signer_type="s3_query",
            method="GET",
            url="https://examplebucket.s3.us-east-1.amazonaws.com/key?x=%2f",
            service="s3",
            expires_in=900,
        ),
        sign_request(
            id="presign_s3_object_lambda",
            kind="presign",
            signer_type="s3_query",
            method="GET",
            url="https://my-ol-ap-123456789012.s3-object-lambda.us-east-1.amazonaws.com/a%20b.txt",
            service="s3-object-lambda",
            expires_in=900,
        ),
        sign_request(
            id="s3express_header",
            kind="header",
            signer_type="s3express",
            method="GET",
            url="https://bucket--use1-az4--x-s3.s3express-use1-az4.us-east-1.amazonaws.com/a%20b.txt",
            service="s3express",
            session_token="SESSION_TOKEN",
            s3express_session=True,
        ),
        sign_request(
            id="presign_s3express",
            kind="presign",
            signer_type="s3express_query",
            method="GET",
            url="https://bucket--use1-az4--x-s3.s3express-use1-az4.us-east-1.amazonaws.com/a%20b.txt",
            service="s3express",
            expires_in=900,
            session_token="SESSION_TOKEN",
            s3express_session=True,
        ),
        sign_request(
            id="s3express_control",
            kind="header",
            signer_type="s3",
            method="GET",
            url="https://s3express-control.us-east-1.amazonaws.com/v20180820/bucket",
            service="s3express",
            session_token="SESSION_TOKEN",
        ),
        sign_request(
            id="s3express_create_session",
            kind="header",
            signer_type="s3",
            method="GET",
            url="https://bucket--use1-az4--x-s3.s3express-use1-az4.us-east-1.amazonaws.com/?session",
            service="s3express",
            session_token="SESSION_TOKEN",
        ),
        sign_request(
            id="get-vanilla-utf8-query",
            kind="header",
            signer_type="sigv4",
            method="GET",
            url="https://example.amazonaws.com/?ሴ=bar",
            service="service",
            secret_access_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            timestamp="20150830T123600Z",
            apply_checksum_header=False,
            source="aws-sig-v4-test-suite",
            query_via_params=True,
        ),
        sign_request(
            id="query_plus",
            kind="header",
            signer_type="sigv4",
            method="GET",
            url="https://x.execute-api.us-east-1.amazonaws.com/?x=a+b",
            service="execute-api",
            headers={"x-amz-content-sha256": EMPTY_SHA256},
            query_via_params=True,
        ),
        sign_request(
            id="query_tilde_lower",
            kind="header",
            signer_type="sigv4",
            method="GET",
            url="https://x.execute-api.us-east-1.amazonaws.com/?x=%7e",
            service="execute-api",
            headers={"x-amz-content-sha256": EMPTY_SHA256},
            query_via_params=True,
        ),
        sign_request(
            id="query_hex_lower",
            kind="header",
            signer_type="sigv4",
            method="GET",
            url="https://x.execute-api.us-east-1.amazonaws.com/?x=%2f",
            service="execute-api",
            headers={"x-amz-content-sha256": EMPTY_SHA256},
            query_via_params=True,
        ),
    ]

    api_base = "https://x.execute-api.us-east-1.amazonaws.com"
    s3_base = "https://b.s3.us-east-1.amazonaws.com"
    raw_paths = ["/a//b", "/a/./b", "/a/x/../b"]

    tab_lines = canonical_lines(
        "s3",
        "s3",
        "PUT",
        f"{s3_base}/k",
        headers={"x-amz-meta-t": "a\t\tb  c "},
    )
    tab_header_line = next(line for line in tab_lines if line.startswith("x-amz-meta-t:"))

    dup_lines = canonical_lines(
        "s3",
        "s3",
        "GET",
        f"{s3_base}/k",
        headers=[("x-amz-meta-tag", "a"), ("x-amz-meta-tag", "a")],
    )
    dup_header_line = next(line for line in dup_lines if line.startswith("x-amz-meta-tag:"))

    fragments = {
        "path_norm_api": {
            path: canonical_lines("sigv4", "execute-api", "GET", api_base + path)[1]
            for path in raw_paths
        },
        "path_norm_s3": {
            path: canonical_lines("s3", "s3", "GET", s3_base + path)[1]
            for path in raw_paths
        },
        "tab_header": {
            "input": "a\t\tb  c ",
            "canonical_line": tab_header_line,
            "canonical_value": tab_header_line.split(":", 1)[1],
        },
        "dup_header_list": {
            "input": [["x-amz-meta-tag", "a"], ["x-amz-meta-tag", "a"]],
            "canonical_line": dup_header_line,
            "canonical_value": dup_header_line.split(":", 1)[1],
        },
        "query_canonical": {
            "x=a%2Bb": canonical_lines("sigv4", "execute-api", "GET", f"{api_base}/?x=a%2Bb")[2],
            "x=~": canonical_lines("sigv4", "execute-api", "GET", f"{api_base}/?x=~")[2],
            "b=2&a=1&a=0": canonical_lines(
                "sigv4", "execute-api", "GET", f"{api_base}/?b=2&a=1&a=0"
            )[2],
        },
    }

    return {
        "botocore_version": botocore.__version__,
        "shared": {
            "access_key_id": ACCESS_KEY,
            "secret_access_key": SECRET_KEY,
            "region": REGION,
            "timestamp": TIMESTAMP,
        },
        "vectors": vectors,
        "fragments": fragments,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify that test/fixtures/sigv4_vectors.json matches botocore.",
    )
    parser.add_argument(
        "--allow-any-botocore",
        action="store_true",
        help="Skip the pinned botocore version check.",
    )
    args = parser.parse_args()

    if not args.allow_any_botocore and botocore.__version__ != EXPECTED_BOTOCORE_VERSION:
        print(
            f"Expected botocore {EXPECTED_BOTOCORE_VERSION}, got {botocore.__version__}",
            file=sys.stderr,
        )
        return 1

    expected = json.dumps(build_vectors(), indent=2, sort_keys=False) + "\n"

    if args.check:
        if not FIXTURE.exists():
            print(f"{FIXTURE} does not exist", file=sys.stderr)
            return 1
        actual = FIXTURE.read_text(encoding="utf-8")
        if actual != expected:
            print(f"{FIXTURE} is out of date with botocore {botocore.__version__}", file=sys.stderr)
            return 1
        return 0

    FIXTURE.parent.mkdir(parents=True, exist_ok=True)
    FIXTURE.write_text(expected, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
