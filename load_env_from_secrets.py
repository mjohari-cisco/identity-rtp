#!/usr/bin/env python3
import argparse
import base64
import json
import os
import sys

import boto3
from botocore.exceptions import ClientError


DEFAULT_KEYS = ["DB_INSTANCE_NAME"]


def _parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Load selected keys from an AWS Secrets Manager JSON secret into "
            "process environment and optionally print shell exports."
        )
    )
    parser.add_argument("--secret-id", required=True, help="Secrets Manager secret name or ARN")
    parser.add_argument(
        "--region",
        default=None,
        help="AWS region (optional; defaults to AWS config or ARN)",
    )
    parser.add_argument(
        "--profile",
        default=None,
        help="AWS profile name to use for authentication (optional)",
    )
    parser.add_argument(
        "--keys",
        nargs="+",
        default=DEFAULT_KEYS,
        help="One or more keys to load from the secret JSON",
    )
    parser.add_argument(
        "--print-export",
        action="store_true",
        help="Print export statements for loaded keys to stdout",
    )
    parser.add_argument(
        "--dotenv",
        default=None,
        help="Write loaded keys to a dotenv file (e.g., .env)",
    )
    return parser.parse_args()


def _resolve_region(secret_id, region):
    if region:
        return region
    if secret_id.startswith("arn:"):
        parts = secret_id.split(":")
        if len(parts) > 3 and parts[2] == "secretsmanager":
            arn_region = parts[3]
            if arn_region:
                return arn_region
    return None


def _get_secret_json(secret_id, region, profile):
    resolved_region = _resolve_region(secret_id, region)
    session = (
        boto3.Session(profile_name=profile, region_name=resolved_region)
        if resolved_region
        else boto3.Session(profile_name=profile)
    )

    candidate_regions = []
    if resolved_region:
        candidate_regions.append(resolved_region)
    else:
        default_region = session.region_name
        if default_region:
            candidate_regions.append(default_region)
        for candidate in session.get_available_regions("secretsmanager"):
            if candidate not in candidate_regions:
                candidate_regions.append(candidate)

    last_exc = None
    for candidate in candidate_regions:
        client = session.client("secretsmanager", region_name=candidate)
        try:
            resp = client.get_secret_value(SecretId=secret_id)
        except ClientError as exc:
            error_code = exc.response.get("Error", {}).get("Code")
            if error_code == "ResourceNotFoundException":
                last_exc = exc
                continue
            raise
        if "SecretString" in resp:
            secret_str = resp["SecretString"]
        else:
            secret_str = base64.b64decode(resp["SecretBinary"]).decode("utf-8")
        try:
            return json.loads(secret_str)
        except json.JSONDecodeError as exc:
            raise ValueError("Secret is not valid JSON") from exc

    if last_exc:
        raise last_exc
    raise ValueError("Unable to resolve secret region")


def _write_dotenv(path, values):
    lines = [f"{key}={value}" for key, value in values.items()]
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


def main():
    args = _parse_args()
    secret_json = _get_secret_json(args.secret_id, args.region, args.profile)

    missing = [key for key in args.keys if key not in secret_json]
    if missing:
        print(f"Missing keys in secret: {', '.join(missing)}", file=sys.stderr)
        sys.exit(1)

    values = {key: str(secret_json[key]) for key in args.keys}
    for key, value in values.items():
        os.environ[key] = value

    if args.dotenv:
        _write_dotenv(args.dotenv, values)

    if args.print_export:
        for key, value in values.items():
            print(f"export {key}={value}")


if __name__ == "__main__":
    main()
