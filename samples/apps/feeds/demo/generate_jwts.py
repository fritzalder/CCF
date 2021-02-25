# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import sys
import json
import requests
import random
import argparse
from pathlib import Path

sys.path.append(".")
import create_jwt


def generate_npm_feed(data_dir: Path):
    issuer = f"localhost/npm"  # localhost for local testing

    npm_search_url = (
        "https://registry.npmjs.org/-/v1/search?text=%22js%22&size=5"  # 250 max
    )
    print(f"Fetching {npm_search_url}")
    r = requests.get(npm_search_url)
    r.raise_for_status()
    pkgs = r.json()["objects"]
    for pkg in pkgs:
        pkg_name = pkg["package"]["name"]
        subject = pkg_name.replace("/", "_")
        url = f"https://registry.npmjs.org/{pkg_name}/latest"
        print(f"Fetching {url}")
        r = requests.get(url)
        r.raise_for_status()
        pkg_info = r.json()
        pkg_info["iss"] = issuer
        pkg_info["sub"] = subject

        create_jwt.write_jwt(data_dir, pkg_info)


def generate_contoso_feed(data_dir: Path):
    issuer = f"localhost/contoso"  # localhost for local testing

    npm_feed_dir = data_dir / "npm"
    found = False
    for npm_receipt_path in npm_feed_dir.glob("*.receipt.json"):
        found = True
        print(f"Reading {npm_receipt_path}")
        with open(npm_receipt_path) as f:
            npm_receipt = json.load(f)

        subject = npm_receipt["data"]["subject"] + "-audit"
        audit = {
            "iss": issuer,
            "sub": subject,
            "artifactReference": {
                "iss": npm_receipt["data"]["issuer"],
                "sub": npm_receipt["data"]["subject"],
                "seqno": npm_receipt["data"]["seqno"],
                "hash": "tbd",
            },
            "status": random.choice(["approved", "rejected"]),
        }

        create_jwt.write_jwt(data_dir, audit)

    if not found:
        print('No receipts in npm feed folder found, run "submit_jwts.py npm" first')

def main(args):
    data_dir = Path("data")
    data_dir.mkdir(exist_ok=True)

    if args.issuer == "npm":
        generate_npm_feed(data_dir)
    elif args.issuer == "contoso":
        generate_contoso_feed(data_dir)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("issuer", choices=["npm", "contoso"])
    args = parser.parse_args()

    main(args)
