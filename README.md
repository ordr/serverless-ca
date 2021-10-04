# ORDR Serverless CA

This lambda function operates as a lightweight serverless certificate authority.

While it can be used to generate TLS certificates for any internal or private 
infrastructure, we use it to solve the chicken-and-egg problem of Hashicorp
Vault TLS connectivity.

Private key generation happens on the server, and it never leaves it. This
function does not receive or generate private keys. `openssl` or similar is
still required on the calling host.

## First setup

First of all, generate a Certificate Authority private key and a long-lasting
CA certificate file:

```bash
openssl ecparam -genkey -name secp256r1 -out ca.key
openssl req -x509 -new -SHA256 -nodes -key ca.key -days 73000 -out ca.crt
```

Once you have your two files, create an AWS Secrets Manager secret with a value
like this:

```json
{
    "privateKey": "<base64 encoded PEM private key file>",
    "certificate": "<base64 encode PEM certificate file>"
}
```

Compile, package the code and release the function:
```bash
make
terraform apply
```

**Make sure to restrict access to the secret and the function as much as
possible. Eg: only the function can access the secret; only a given EC2 instance
role can call the function. Whomever can access the secret or the function owns
your infrastructure.**

*Once you've stored and protected the secret, it is wise to wipe the two files 
from your machine.*

## Generating a certificate

On your instance:
- Generate a private key file:
```bash
openssl ecparam -genkey -name secp256r1 -out server.key
```
- Generate a Certificate Signing Request
```bash
openssl req -new -SHA256 -nodes -key server.key -out server.csr
```
- Invoke the lambda function with the CSR file base64 encoded:
```bash
aws lambda invoke --function-name my-function --payload '{ "csr": "<base64 encode PEM CSR file>" }' response.json
{
    "csr": "<base64 encoded PEM CSR file>"
}
```

Upon success, the function returns the CA-signed server certificate and the
CA certificate itself. Depending on the software you're trying to configure
you might have to specify both files (and the private key), or to
concatenate the two (or neither).

### Example: generic web server certificates

```bash
openssl ecparam -genkey -name secp256r1 -out server.key
openssl req -new -SHA256 -nodes -key server.key -subj "/C=GB/ST=England/L=London/O=ORDR/CN=privatestuff.ordr.menu" -out server.csr
aws lambda invoke --function-name my-function --payload "{ \"csr\": \"$(base64 -w0 server.csr)\" }" response.json

mv server.key /etc/nginx/ssl/server.key
jq -r .certificate response.json | base64 -d > /etc/nginx/ssl/server.crt
```

## CA expiration

The example Certificate Authority is set to expire in 20 years.

If your startup still exists in 20 years (first of all: congratulations!), you
are now headed for a catastrophe where nothing connects to anything anymore.

To avoid that, use short-lived certificates (< 3 months), set up cron jobs to
refresh them, and mark a date in your calendar 19 years from now.

When the alarm fires, regenerate the CA, and replace the AWS secret.

Your cron jobs now have 9/12 months to fire and fetch fresh new certificates
signed by the new authority.

If you have set up browsers and OS to trust the CA, you might have to do that
again.