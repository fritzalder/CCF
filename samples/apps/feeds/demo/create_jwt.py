# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import sys
import base64
import json
import re
import argparse
from pathlib import Path

sys.path.append("../../../tests")
import infra.crypto


def write_jwt(data_dir: Path, claims: dict):
    issuer = claims.get('iss')
    if not issuer:
        raise ValueError('"iss" claim missing')
    issuer_re = r'localhost/([\w-]+)'
    match = re.match(issuer_re, issuer)
    if not match:
        raise ValueError(f'for this demo, "iss" claim must match {issuer_re}')
    name = match.group(1)

    subject = claims.get('sub')
    if not subject:
        raise ValueError('"sub" claim missing')

    feed_dir = data_dir / name
    feed_dir.mkdir(exist_ok=True)

    jwt_key_priv_pem, jwt_cert_pem = create_or_load_keypair(feed_dir)

    json_path = feed_dir / f"{subject}.json".replace("/", "_")
    with open(json_path, "w") as f:
        json.dump(claims, f, indent=2)

    jwt = infra.crypto.create_jwt(
        claims, jwt_key_priv_pem, key_id=name, cert_pem=jwt_cert_pem
    )
    jwt_path = feed_dir / f"{subject}.jwt".replace("/", "_")
    print(f"Writing {jwt_path}")
    with open(jwt_path, "w") as f:
        f.write(jwt)


def create_or_load_keypair(feed_dir: Path):
    key_path = feed_dir / 'key.pem'
    cert_path = feed_dir / 'cert.pem'
    if key_path.exists():
        with open(key_path) as f:
            jwt_key_priv_pem = f.read()
        with open(cert_path) as f:
            jwt_cert_pem = f.read()
    else:
        print('No signing key found, generating...')
        jwt_key_priv_pem, _ = infra.crypto.generate_rsa_keypair(2048)
        jwt_cert_pem = infra.crypto.generate_cert(jwt_key_priv_pem)
        print(f"Writing {key_path}")
        with open(key_path, 'w') as f:
            f.write(jwt_key_priv_pem)
        print(f"Writing {cert_path}")
        with open(cert_path, 'w') as f:
            f.write(jwt_cert_pem)
        write_jwks(feed_dir, jwt_cert_pem)

    return jwt_key_priv_pem, jwt_cert_pem


def write_jwks(feed_dir, jwt_cert_pem):
    jwt_jwks_path = feed_dir / "certs"
    print(f"Writing {jwt_jwks_path}")
    with open(jwt_jwks_path, "w") as f:
        jwks = create_jwks(feed_dir.name, jwt_cert_pem)
        json.dump(jwks, f, indent=2)
    well_known_dir = feed_dir / ".well-known"
    well_known_dir.mkdir(exist_ok=True)
    discovery_path = well_known_dir / "openid-configuration"
    print(f"Writing {discovery_path}")
    with open(discovery_path, "w") as f:
        json.dump({"jwks_uri": f"https://localhost/{feed_dir.name}/certs"}, f)


def create_jwks(kid, cert_pem):
    der_b64 = base64.b64encode(infra.crypto.cert_pem_to_der(cert_pem)).decode("ascii")
    return {"keys": [{"kty": "RSA", "kid": kid, "x5c": [der_b64]}]}


def main(args):
    data_dir = Path("data")
    data_dir.mkdir(exist_ok=True)

    with open(args.claims) as f:
        claims = json.load(f)

    write_jwt(data_dir, claims)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("claims", type=Path, help='Path to JSON file with claims')
    args = parser.parse_args()

    main(args)
