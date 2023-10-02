# YubiKey Sign CSR

yubikey-sign-csr is a command line utility to sign X.509 Certificate Signing Requests (CSRs) using a Certificate Authority stored on a YubiKey.

## Installation

To install from source, run:

```sh
go install github.com/jamescun/yubikey-sign-csr@latest
```

## Usage

To list the Yubikeys connected to your machine, run:

```sh
yubikey-sign-csr --list-keys
```

By default, the first key (if any) will be used.

To sign a CSR, run:

```sh
yubikey-sign-csr --csr csr.pem
```

Which will output the certificate.

If your private key requires a PIN, it will be requested.

If your private key requires touch, you must touch your YubiKey before the certificate will be generated.

To specify key usage, use `--ca`, `--server` and/or `--client` to generate a certificate that is a certificate authority, can be used for server authentication, and/or can be used for client authentication.
