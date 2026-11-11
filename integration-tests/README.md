# zns-integration-tests

Local process harness for the Zcash Name Service: `zebrad` (regtest), a real
[`zallet`](https://github.com/zcash/zallet) wallet as the user, and
`zns-mint`. Mint is built with `--features regtest` from this workspace
(override with `$ZNS_MINT_BIN`). If no capsule is provided, the harness
seals an all-zero seed with the public test key.

Before mint starts, a funder **Zallet wallet** mines coinbase on the empty
chain and shields it, then pays the user's wallet and the all-zero-seed
Treasury t-addr by transfer. The Treasury's keys publish a **dev**
ceremony: 40 zero-value Registry Ironwood notes plus a Treasury Ironwood
note. That first Ironwood bundle is 42 actions (proving takes a couple of
minutes).

The wallets are Zallet (`$ZALLET_BIN`, or `zallet-zebra` on `$PATH`):
build the zebra backend of a zallet checkout with
`cargo build --locked --release` in `backends/zebra` and point `ZALLET_BIN`
at `target/release/zallet-zebra`. Use the zebrad release and zallet commit
that `.github/workflows/ci.yml` pins. The user pays requests through
`z_sendfromaccount`.

Both tests are built on the `fixture` module:

- `tests/happy_path.rs`: claim → update → release. Pull requests run it.
- `tests/reorg.rs`: the mint's queues across live reorgs. The Daily
  workflow runs it.

## License

MIT. See [LICENSE](LICENSE).
