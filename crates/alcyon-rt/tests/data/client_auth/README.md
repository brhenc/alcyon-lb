# Client certificate authentication fixtures (T655 slice C1a)

- `common.pem`, `ca-auth.crt`, `client1.pem`: copied from HAProxy 3.5-dev11
  `reg-tests/ssl/certs/`. `ca-auth.crt` is X.509 v3 (`CA:TRUE`), while `client1.pem`
  is X.509 v1 (accepted by HAProxy/OpenSSL, refused by `rustls-webpki` with
  `UnsupportedCertVersion`).
- `v3-ca.crt`, `v3-client-valid.pem`, `v3-client-expired.pem`: X.509 v3 client-auth
  fixtures generated with OpenSSL 4.0.3 using the commands below:

```sh
cat > /tmp/ca.cnf <<'EOF'
[req]
distinguished_name = dn
x509_extensions = v3_ca
prompt = no
[dn]
C = FR
O = Alcyon Test
CN = Alcyon Test Client Auth CA v3
[v3_ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
EOF

cat > /tmp/client.cnf <<'EOF'
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
EOF

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout /tmp/v3-ca.key -out v3-ca.crt \
  -config /tmp/ca.cnf -not_before 20200101000000Z -not_after 20500101000000Z

openssl req -newkey rsa:2048 -nodes \
  -keyout /tmp/v3-client-valid.key -out /tmp/v3-client-valid.csr \
  -subj "/C=FR/O=Alcyon Test/CN=v3-client-valid"
openssl x509 -req -in /tmp/v3-client-valid.csr \
  -CA v3-ca.crt -CAkey /tmp/v3-ca.key -CAcreateserial \
  -extfile /tmp/client.cnf -not_before 20200101000000Z -not_after 20500101000000Z \
  -out /tmp/v3-client-valid.crt
cat /tmp/v3-client-valid.crt /tmp/v3-client-valid.key > v3-client-valid.pem

openssl req -newkey rsa:2048 -nodes \
  -keyout /tmp/v3-client-expired.key -out /tmp/v3-client-expired.csr \
  -subj "/C=FR/O=Alcyon Test/CN=v3-client-expired"
openssl x509 -req -in /tmp/v3-client-expired.csr \
  -CA v3-ca.crt -CAkey /tmp/v3-ca.key -CAcreateserial \
  -extfile /tmp/client.cnf -not_before 20200101000000Z -not_after 20210101000000Z \
  -out /tmp/v3-client-expired.crt
cat /tmp/v3-client-expired.crt /tmp/v3-client-expired.key > v3-client-expired.pem
```
