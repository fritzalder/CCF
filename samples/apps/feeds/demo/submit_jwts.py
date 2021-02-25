# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import os
import json
import tempfile
import argparse
from pathlib import Path
from http import HTTPStatus

import ccf.clients
import ccf.proposal_generator

CCF_HOST_DEFAULT = "127.0.0.1"
CCF_PORT_DEFAULT = "8000"
CCF_WORKSPACE = "workspace/sandbox_common"
CCF_CA = os.path.join(CCF_WORKSPACE, "networkcert.pem")
CCF_MEMBER_KEY = os.path.join(CCF_WORKSPACE, "member0_privk.pem")
CCF_MEMBER_CERT = os.path.join(CCF_WORKSPACE, "member0_cert.pem")


def populate_feed(data_dir: Path, issuer_name: str, ccf_host: str, ccf_port: str):
    client = ccf.clients.CCFClient(ccf_host, ccf_port, CCF_CA)

    feed_dir = data_dir / issuer_name

    # temporary until cert fetching moves to app
    jwt_issuer = f"https://localhost/{issuer_name}"
    tls_cert_path = data_dir / "tls_cert.pem"
    propose_jwt_issuer(jwt_issuer, tls_cert_path, feed_dir, ccf_host, ccf_port)

    r = client.post(f"/app/register", {"issuer": f"localhost/{issuer_name}"})
    assert r.status_code in [HTTPStatus.OK.value, HTTPStatus.CREATED.value]

    paths = []
    for jwt_path in feed_dir.glob("*.jwt"):
        with open(jwt_path) as f:
            jwt = f.read()
        r = client.post(f"/app/submit", jwt)
        assert r.status_code == HTTPStatus.CREATED.value
        data = r.body.json()

        client.wait_for_commit(r)
        r = client.get(f"/app/receipt?commit={r.seqno}")
        receipt = r.body.json()

        receipt_path = feed_dir / f"{jwt_path.stem}.receipt.json"
        with open(receipt_path, "w") as f:
            combined = {**receipt, "data": data}
            json.dump(combined, f, indent=2)
        paths.append((jwt_path, receipt_path, combined["data"]["seqno"]))

    print("Summary:")
    for jwt_path, receipt_path, seqno in paths:
        print(f"Submitted {jwt_path}")
        print(f"Received {receipt_path} @ {seqno}")


def propose_jwt_issuer(issuer, ca_cert_path, feed_dir, ccf_host: str, ccf_port: str):
    # temporary, until this can be moved into the app

    member_client = ccf.clients.CCFClient(
        ccf_host,
        ccf_port,
        CCF_CA,
        session_auth=ccf.clients.Identity(CCF_MEMBER_KEY, CCF_MEMBER_CERT, "member"),
        signing_auth=ccf.clients.Identity(CCF_MEMBER_KEY, CCF_MEMBER_CERT, "member"),
    )

    ca_cert_name = issuer
    proposal, vote = ccf.proposal_generator.set_ca_cert(ca_cert_name, ca_cert_path)

    r = member_client.post(
        "/gov/proposals",
        body=proposal,
    )
    assert r.status_code == HTTPStatus.OK.value

    # temporary to avoid waiting until CCF's JWT cert auto-refresh is done
    jwks_path = feed_dir / "certs"
    with open(jwks_path) as f:
        jwks = json.load(f)

    with tempfile.NamedTemporaryFile("w") as f:
        json.dump(
            {
                "issuer": issuer,
                "auto_refresh": True,
                "ca_cert_name": ca_cert_name,
                "jwks": jwks,
            },
            f,
        )
        f.flush()
        proposal, vote = ccf.proposal_generator.set_jwt_issuer(f.name)
        print(proposal)

    r = member_client.post(
        "/gov/proposals",
        body=proposal,
    )
    assert r.status_code == HTTPStatus.OK.value


def main(args):
    data_dir = Path("data")
    data_dir.mkdir(exist_ok=True)

    populate_feed(data_dir, args.issuer_name, args.host, args.port)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("issuer_name", help='Name of "data" subfolder')
    parser.add_argument("--host", default=CCF_HOST_DEFAULT, help='CCF hostname')
    parser.add_argument("--port", default=CCF_PORT_DEFAULT, help='CCF port')
    args = parser.parse_args()

    main(args)
