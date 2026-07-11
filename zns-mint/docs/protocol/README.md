# ZNS Mint Protocol

This directory is the design source for `zns-mint`: the Zcash Name Service mint.

`zns-mint` is the attested issuer for ZNS Name Notes. It runs inside an
attested TEE, derives two ZIP-32 accounts from one seed, scans Zcash chain data,
detects shielded ZNS memos, and creates Orchard Name Notes that encode name
ownership and lifecycle state.


u1hru7mj89zrlrwsa62uywlxpqcqc6nvaxt6vlxestprqa6hfv2vu3uhc9wtnn0tqjnvmaydp3zg0ql2x4drapfplrsaky3mmdelqcu6n9ykasukt47cgav5k7055srupg6z4dfkrlr88kl9plw03jp6ejr8dvqzpzf7yatws7xg6s6fuy


deeksha.zcash

DNS: ICANN
192.168.1.2 <--> deeksha.com 

sangeetha.deeksha.com ->

-> (registry) godaddy/namecheap -> deeksha@gmail.com

ENS (ethereum name service)

bitcoin: money (dumb money)
proof of work 

ethereum: programmable money (smart money)

proof of stake

'smart contracts' <-> custom (your) code

deeksha.eth <-> public address: 0x1234567890abcdef1234567890abcdef12345678

private password: 1234567890abcdef1234567890abcdef12345678 

message: hi i'm deeksha

signature: 0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890

DAO (decentralized autonomous organization): 7 dudes 

Nick Johnson

ZNS (invented/discovered/engineered/designed/created by craftsoldier): zcash name service

problem: 

zcash: money (dumb money)

how do you ensure (proof/certainty/attestation/trust model)

how do you ensure that name owner can only change the address associated with their name and nobody else can change it?

how do you tie state with blockchain


deeksha <-> julian

memo (512bytes): unicode

signature (5kb)

one-time-passocdes with ZCASH (invented by james joseph):


administrator: verification service

deeksha.zcash <->  u1hru7mj89zrlrwsa62uywlxpqcqc6nvaxt6vlxestprqa6hfv2vu3uhc9wtnn0tqjnvmaydp3zg0ql2x4drapfplrsaky3mmdelqcu6n9ykasukt47cgav5k7055srupg6z4dfkrlr88kl9plw03jp6ejr8dvqzpzf7yatws7xg6s6fuy


deeksha sends a message to admin: here's my new address, give me one-time-passcode for deeksha.zcash

administrato sends a one-time-passcode to deeksha.zcash: 123456

deeksha.zcash sends a message to admin: here is my one-time-passcode: 123456

TEE (trusted execution environment): bytes (attestation)

mint name note: 0-value zcash transaction that has custom randomness in some super special cryprography that we changed and since we did that we can now prove to everyone that deeksha.zcash is actually registered to an address

rcm: hash(deeksha.zcash || u1hru7mj89zrlrwsa62uywlxpqcqc6nvaxt6vlxestprqa6hfv2vu3uhc9wtnn0tqjnvmaydp3zg0ql2x4drapfplrsaky3mmdelqcu6n9ykasukt47cgav5k7055srupg6z4dfkrlr88kl9plw03jp6ejr8dvqzpzf7yatws7xg6s6fuy || 123456)



deeksha.zcash

amount: 0.5ZEC
memo: pls register deeksha.zcash

mint: 

resolver:
