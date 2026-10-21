#!/usr/bin/env python3
# /// script
# dependencies = ["botocore==1.42.78"]
# ///
"""Generate lib/aws_auth/signing_names.ex from botocore service models and endpoint data."""

from __future__ import annotations

import argparse
import glob
import gzip
import json
import os
import pathlib
import re
import sys

import botocore

EXPECTED_BOTOCORE_VERSION = "1.42.78"
ROOT = pathlib.Path(__file__).resolve().parent.parent
TARGET = ROOT / "lib" / "aws_auth" / "signing_names.ex"

RULE_HOST_RE = re.compile(
    r"^https?://([a-z0-9.-]+)\."
    r"(?:\{(?:Region|[A-Za-z]+#region|PartitionResult#implicitGlobalRegion)\}|"
    r"cn-north-1|cn-northwest-1|us-east-1|us-west-2|us-gov-west-1|us-gov-east-1|us-gov|global|aws-global)\."
    r"(?:amazonaws\.com(?:\.cn)?|api\.aws|api\.amazonwebservices\.com\.cn|"
    r"\{[A-Za-z]+#(?:dnsSuffix|dualStackDnsSuffix)\})"
)
S3_LEGACY_RE = re.compile(
    r"^s3-(?:fips|dualstack|accelerate|external-1|"
    r"(?:us|eu|ap|sa|ca|me|af|il|cn|eusc)-[a-z0-9-]+-\d)$"
)


def strip_fips_prefix(prefix: str) -> str:
    labels = [lbl for lbl in prefix.split(".") if lbl not in ("fips", "dualstack")]
    normalized = [lbl[:-5] if lbl.endswith("-fips") else lbl for lbl in labels]
    return ".".join(normalized)


def record_mapping(mapping: dict[str, str], endpoint_prefix: str, signing_name: str) -> None:
    if not endpoint_prefix or not signing_name or endpoint_prefix == signing_name:
        return
    if S3_LEGACY_RE.match(endpoint_prefix):
        return
    existing = mapping.get(endpoint_prefix)
    if existing is not None and existing != signing_name:
        raise RuntimeError(
            f"Conflicting signingName for {endpoint_prefix}: {existing} vs {signing_name}"
        )
    mapping[endpoint_prefix] = signing_name


def walk_rule_nodes(node: object, default_signing_name: str, mapping: dict[str, str]) -> None:
    if isinstance(node, dict):
        url = node.get("url")
        if isinstance(url, str):
            auth_schemes = node.get("properties", {}).get("authSchemes", [])
            rule_signing_name = (
                auth_schemes[0].get("signingName") if auth_schemes else None
            ) or default_signing_name
            match = RULE_HOST_RE.match(url)
            if match:
                norm_prefix = strip_fips_prefix(match.group(1))
                record_mapping(mapping, norm_prefix, rule_signing_name)
        for value in node.values():
            walk_rule_nodes(value, default_signing_name, mapping)
    elif isinstance(node, list):
        for item in node:
            walk_rule_nodes(item, default_signing_name, mapping)


def load_divergent_prefixes() -> tuple[dict[str, str], int]:
    data_dir = pathlib.Path(botocore.__file__).resolve().parent / "data"
    mapping: dict[str, str] = {}
    service_to_signing_name: dict[str, str] = {}
    divergent_model_count = 0

    # 1. Model metadata (service-2.json) and endpoint rules (endpoint-rule-set-1.json)
    for service_dir in sorted(os.listdir(data_dir)):
        service_path = data_dir / service_dir
        if not service_path.is_dir():
            continue

        files = sorted(glob.glob(str(service_path / "*" / "service-2.json*")))
        if not files:
            continue

        latest = files[-1]
        if latest.endswith(".gz"):
            with gzip.open(latest, "rt", encoding="utf-8") as fh:
                model = json.load(fh)
        else:
            with open(latest, "r", encoding="utf-8") as fh:
                model = json.load(fh)

        metadata = model.get("metadata", {})
        endpoint_prefix = metadata.get("endpointPrefix")
        signing_name = metadata.get("signingName")
        effective_signing_name = signing_name or endpoint_prefix

        if endpoint_prefix and effective_signing_name:
            service_to_signing_name[service_dir] = effective_signing_name
            service_to_signing_name[endpoint_prefix] = effective_signing_name
            service_to_signing_name[effective_signing_name.lower()] = effective_signing_name

        if endpoint_prefix and signing_name and signing_name != endpoint_prefix:
            divergent_model_count += 1
            record_mapping(mapping, endpoint_prefix, signing_name)

        rule_files = sorted(glob.glob(str(service_path / "*" / "endpoint-rule-set-1.json*")))
        if rule_files and effective_signing_name:
            latest_rule = rule_files[-1]
            if latest_rule.endswith(".gz"):
                with gzip.open(latest_rule, "rt", encoding="utf-8") as fh:
                    rule_data = json.load(fh)
            else:
                with open(latest_rule, "r", encoding="utf-8") as fh:
                    rule_data = json.load(fh)

            walk_rule_nodes(rule_data, effective_signing_name, mapping)

    # 2. Partition endpoint declarations (endpoints.json)
    endpoints_path = data_dir / "endpoints.json"
    with open(endpoints_path, "r", encoding="utf-8") as fh:
        endpoints_data = json.load(fh)

    for partition in endpoints_data.get("partitions", []):
        dns_suffix = partition.get("dnsSuffix", "")
        regions = set(partition.get("regions", {}).keys())
        for service_key, service_def in sorted(partition.get("services", {}).items()):
            default_scope = service_def.get("defaults", {}).get("credentialScope", {})
            default_sn = default_scope.get("service")
            if default_sn:
                record_mapping(mapping, service_key, default_sn)
            effective_default_sn = default_sn or service_to_signing_name.get(
                service_key, service_key
            )
            for _ep_name, ep_def in sorted(service_def.get("endpoints", {}).items()):
                ep_scope = ep_def.get("credentialScope", {})
                ep_sn = ep_scope.get("service")
                if ep_sn:
                    record_mapping(mapping, service_key, ep_sn)
                sn = ep_sn or effective_default_sn
                host = ep_def.get("hostname", "")
                if dns_suffix and host.endswith("." + dns_suffix):
                    rem = host[: -(len(dns_suffix) + 1)]
                    parts = rem.split(".")
                    if len(parts) >= 2 and (
                        parts[-1] in regions or parts[-1] in ("us-gov", "global", "aws-global")
                    ):
                        norm_prefix = strip_fips_prefix(".".join(parts[:-1]))
                        record_mapping(mapping, norm_prefix, sn)

    return dict(sorted(mapping.items())), divergent_model_count


def render_elixir(mapping: dict[str, str], model_count: int) -> str:
    entries = "\n".join(f'    "{ep}" => "{sn}",' for ep, sn in sorted(mapping.items()))
    if entries.endswith(","):
        entries = entries[:-1]

    return f"""# Generated by scripts/gen_signing_names.py from botocore {botocore.__version__} ({model_count} models, {len(mapping)} unique prefixes).
# Do not edit by hand; run `python3 scripts/gen_signing_names.py` to regenerate.
defmodule AWSAuth.SigningNames do
  @moduledoc false

  @endpoint_to_signing_name %{{
{entries}
  }}

  @spec endpoint_to_signing_name() :: %{{optional(String.t()) => String.t()}}
  def endpoint_to_signing_name, do: @endpoint_to_signing_name

  @spec fetch(String.t()) :: {{:ok, String.t()}} | :error
  def fetch(endpoint_prefix), do: Map.fetch(@endpoint_to_signing_name, endpoint_prefix)

  @spec get(String.t(), String.t() | nil) :: String.t() | nil
  def get(endpoint_prefix, default \\\\ nil),
    do: Map.get(@endpoint_to_signing_name, endpoint_prefix, default)
end
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify that lib/aws_auth/signing_names.ex matches botocore.",
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

    mapping, model_count = load_divergent_prefixes()
    expected = render_elixir(mapping, model_count)

    if args.check:
        if not TARGET.exists():
            print(f"{TARGET} does not exist", file=sys.stderr)
            return 1
        actual = TARGET.read_text(encoding="utf-8")
        if actual != expected:
            print(f"{TARGET} is out of date with botocore {botocore.__version__}", file=sys.stderr)
            return 1
        return 0

    TARGET.write_text(expected, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
