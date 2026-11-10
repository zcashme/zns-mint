# zns-integration-tests

Local process harness for the Zcash Name Service: `zebrad` (regtest), a real
[`zallet`](https://github.com/zcash/zallet) wallet as the user, and
`zns-mint`. Mint is built with `--features regtest` from this workspace
(override with `$ZNS_MINT_BIN`). If no capsule is provided, the harness
seals an all-zero seed with the public test key.

Before mint starts, the harness mines 104 blocks and publishes a **dev**
ceremony: 40 zero-value Registry Ironwood notes plus a Treasury Ironwood
note, funded from coinbase paid to the all-zero-seed Treasury t-addr.
That first Ironwood bundle is 42 actions (proving takes a couple of minutes).

The user is a **Zallet wallet** (`$ZALLET_BIN`, or `zallet-zebra` on
`$PATH`): build the zebra backend of a zallet checkout with
`cargo build --locked --release` in `backends/zebra` and point `ZALLET_BIN`
at `target/release/zallet-zebra`. The harness provisions a fresh regtest
wallet (encryption identity, generated mnemonic, account 0 + miner
address), mines coinbase to it, shields with `z_shieldcoinbase`, and pays
claims through `z_sendfromaccount`.

The claim → update → release flow is `tests/happy_path.rs`, built on the
`fixture` module.

## License

MIT. See [LICENSE](LICENSE).
