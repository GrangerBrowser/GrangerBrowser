# Address Format

## Canonical identity address

A service has one Ed25519 identity key pair. Its canonical identifier is:

```text
SHA-256("granger-network-v0.1/service-id\0" || raw_ed25519_public_key)
```

The 32-byte digest is encoded as unpadded lower-case Base32. The result is a
52-character label followed by `.granger`:

```text
<52 lower-case base32 characters>.granger
```

The full digest is retained; v0.1 does not use shortened identifiers such as
`a81f92d73.granger`. A full canonical label uses only `a-z` and `2-7`.

The domain-separation prefix prevents the same raw hash input convention from
being silently reused by an unrelated protocol. A client recomputes the label
from the descriptor's public key and rejects a mismatch.

## Local aliases

A user may install a local convenience alias such as:

```text
test.granger
```

An alias is one ASCII label containing lower-case letters, digits, or interior
hyphens. It is stored only in the client's local registry and maps to a canonical
identity address. It is not queried through DNS, not globally registered, and
not guaranteed to mean the same service on another machine.

Alias integrity depends on the local registry. Security-sensitive sharing
should use the canonical address or distribute the expected identity through an
authenticated channel.

## Rejected forms

Version 0.1 rejects:

- names outside `.granger`;
- subdomains or multiple labels such as `www.test.granger`;
- Unicode and internationalized labels;
- empty, leading-hyphen, trailing-hyphen, or overlong labels;
- shortened canonical hashes;
- unknown local aliases.

Rejection is terminal. The name is never forwarded to DNS or another resolver.
