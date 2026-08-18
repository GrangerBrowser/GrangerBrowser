# i2pd runtime metadata

Granger Browser packages the official PurpleI2P i2pd Windows x64 MinGW build as
its managed I2P router.

- Upstream: https://github.com/PurpleI2P/i2pd
- Version: 2.61.0
- Release: https://github.com/PurpleI2P/i2pd/releases/tag/2.61.0
- Asset: `i2pd_2.61.0_win64_mingw.zip`
- SHA-256: `A0A8FB199A6BC5B487DF71567791DE6997050B921D65622EF9E936FFA88BC83F`
- License: BSD-3-Clause; see `LICENSE`

The binary archive is a verified build input under ignored `output/` storage.
It is not committed to the source branch. `scripts/fetch-i2p-runtime.ps1`
downloads only the pinned official release asset, verifies the archive hash,
and stages the executable and certificate bundle for release packaging.

The compiled first-run address-book snapshot in
`granger/resources/i2p/hosts.txt` was retrieved through I2P from the default
i2pd 2.61.0 subscription endpoint
`http://shx5vqsw7usdaunyzr2qmes2fq37oumybpudrd4jjj4e4vk4uusa.b32.i2p/hosts.txt`.
Its SHA-256 is
`4EA21E8A9C631A60382DAF23BD90D0BAE0CAB742B93B21BBF3BD885F05F78000`.
It seeds only an empty profile; i2pd's configured `reg.i2p` subscription owns
subsequent updates in the writable user-data directory.
