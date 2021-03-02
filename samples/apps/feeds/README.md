Terminal 1:

```sh
IP=$(hostname -i | tr -d "[:blank:]")
DNSNAME=<NAME>.uksouth.cloudapp.azure.com
PORT=8000
./start.sh -n local://$IP:$PORT,$DNSNAME:$PORT --san dNSName:$DNSNAME
```

Terminal 2:

```sh
python demo/generate_tls_cert.py
# need sudo for port 443
sudo python3 demo/start_issuer_server.py
```

Terminal 3:

```sh
python demo/generate_jwts.py npm
python demo/submit_jwts.py npm --host $DNSNAME --port $PORT
# contoso references npm receipts, hence the command ordering
python demo/generate_jwts.py contoso
python demo/submit_jwts.py contoso --host $DNSNAME --port $PORT
# custom claims file (note: "iss" must be "localhost/<name>")
python demo/create_jwt.py demo/sample-claims.json
python demo/submit_jwts.py sample --host $DNSNAME --port $PORT
```
