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
rm -f v3-ca.srl
```

## CRL, chain, and `ca-verify-file` fixtures (T655 slice C1b)

- `crl-root-ca.crt`, `crl-inter1.crt`, `crl-inter2-revoked.crt`, `crl-inter3-expired.crt`,
  `crl-ca-verify-only.crt`, `crl-leaf-*.pem`, `crl-direct-*.pem`, `crl-cab-leaf.pem`,
  `crl-root.pem`, `crl-inter1.pem`, `crl-all.pem`, `crl-root-expired.pem`: X.509 v3 certificates
  and X.509 v2 SHA-256 CRLs generated with OpenSSL 4.0.3 in `/tmp/c1b_gen_fixtures`.
  CA private keys and OpenSSL CA databases are kept in `/tmp` only and are not checked into
  the tree.

```sh
# Each CA (root, inter1, inter2, inter3, cab) has an OpenSSL CA database in /tmp/c1b_gen_fixtures
# with `default_md = sha256`, `default_crl_days = 8500`, `crlnumber` initialized to 1000 (so
# `openssl ca -gencrl` emits RFC 5280 v2 CRLs), `v3_ca` (`CA:TRUE`, `keyCertSign,cRLSign`), and
# `v3_client` (`CA:FALSE`, `digitalSignature`, `extendedKeyUsage = clientAuth`).
#
# 1. Self-sign Root CA (`Alcyon Test CRL Root CA v3`) and independent CA B
#    (`Alcyon Test CA-Verify-Only B v3`) for 2020-01-01..2050-01-01.
# 2. Sign Inter1 (2020..2050), Inter2 (2020..2050, then revoked by Root),
#    and Inter3 (2020..2021, expired) with Root CA.
# 3. Sign client leaves:
#    - under Inter1: crl-leaf-ok (valid), crl-leaf-revoked (revoked by Inter1),
#      crl-leaf-expired (2020..2021).
#    - under Inter2 (revoked): crl-leaf-under-rev-inter (valid),
#      crl-leaf-exp-under-rev-inter (2020..2021).
#    - under Inter3 (expired): crl-leaf-under-exp-inter (valid).
#    - directly under Root: crl-direct-ok (valid), crl-direct-revoked (revoked by Root).
#    - directly under CA B: crl-cab-leaf (valid).
# 4. Revoke inter2.crt and direct_revoked.crt in Root; revoke leaf_revoked.crt in Inter1.
# 5. Generate v2 CRLs with `openssl ca -batch -config <ca>.cnf -gencrl`:
#    - crl-root.pem (Root), crl-inter1.pem (Inter1),
#    - crl-all.pem (concatenation of Root, Inter1, Inter2, and Inter3 CRLs),
#    - crl-root-expired.pem (`-crlsec 1` followed by waiting 2s so nextUpdate is in the past).
# 6. Copy only the public CA certs, client cert+key PEM bundles, and CRL PEMs here; leave all
#    CA private keys and OpenSSL CA DB files in /tmp.
```
