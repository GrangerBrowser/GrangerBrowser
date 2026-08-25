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

The full digest is retained; Granger Network does not use shortened identifiers such as
`a81f92d73.granger`. A full canonical label uses only `a-z` and `2-7`.

Version 0.4 retains the v0.1 domain-separation prefix so existing identities keep
the same canonical address. This is address-format compatibility, not a wire
protocol downgrade.

The domain-separation prefix prevents the same raw hash input convention from
being silently reused by an unrelated protocol. A client recomputes the label
from the descriptor's public key and rejects a mismatch.

## Aliases

A user may install a local convenience alias such as:

```text
test.granger
```

An alias is one ASCII label containing lower-case letters, digits, or interior
hyphens. The compatibility resolver stores it only in the client's local
registry. The distributed resolver accepts a short-lived service-signed alias
record, but also requires a local alias-to-service identity pin. A self-signature
alone cannot establish global ownership of a human-readable label.

Aliases are never queried through DNS, are not globally registered, and are not
guaranteed to mean the same service on another machine. Security-sensitive
sharing should use the canonical address or distribute and pin the expected
identity through an authenticated channel.

## Rejected forms

Version 0.4 rejects:

- names outside `.granger`;
- subdomains or multiple labels such as `www.test.granger`;
- Unicode and internationalized labels;
- empty, leading-hyphen, trailing-hyphen, or overlong labels;
- shortened canonical hashes;
- unknown or unpinned aliases.

Rejection is terminal. The name is never forwarded to DNS or another resolver.
