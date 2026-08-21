# i2pd runtime metadata

Granger Browser packages official PurpleI2P i2pd x86_64 builds as its managed
I2P router. Windows uses the MinGW archive; the native Linux local RC uses the
Ubuntu Jammy amd64 package.

- Upstream: https://github.com/PurpleI2P/i2pd
- Version: 2.61.0
- Release: https://github.com/PurpleI2P/i2pd/releases/tag/2.61.0
- Asset: `i2pd_2.61.0_win64_mingw.zip`
- SHA-256: `A0A8FB199A6BC5B487DF71567791DE6997050B921D65622EF9E936FFA88BC83F`
- License: BSD-3-Clause; see `LICENSE`

Linux packaging input:

- Asset: `i2pd_2.61.0-1jammy1_amd64.deb`
- SHA-256: `09348999D4561C46037E3CC2AA2B9D76EC7AC3007DB2C1D4A9F92B20B9CA8687`
- Extracted `i2pd` SHA-256: `252823E8F3DDE6232D2A178027D2A249AFA81B7A4595273BCDBE4CD3500852B1`
- Package architecture/version: `amd64`, `2.61.0-1jammy1`

The binary archive is a verified build input under ignored `output/` storage.
It is not committed to the source branch. `scripts/fetch-i2p-runtime.ps1`
downloads only the pinned official release asset, verifies the archive hash,
and stages the executable and certificate bundle for release packaging.
`scripts/fetch-linux-runtimes.sh` applies the equivalent checks to the Linux
package and validates its metadata and extracted binary hash.

The compiled first-run address-book snapshot in
`granger/resources/i2p/hosts.txt` was retrieved through I2P from the default
i2pd 2.61.0 subscription endpoint
`http://shx5vqsw7usdaunyzr2qmes2fq37oumybpudrd4jjj4e4vk4uusa.b32.i2p/hosts.txt`.
Its SHA-256 is
`4EA21E8A9C631A60382DAF23BD90D0BAE0CAB742B93B21BBF3BD885F05F78000`.
It seeds only an empty profile; i2pd's configured `reg.i2p` subscription owns
subsequent updates in the writable user-data directory.
