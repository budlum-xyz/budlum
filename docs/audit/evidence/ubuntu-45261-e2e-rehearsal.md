# Testnet rehearsal report

| Scenario | Result | Detail |
|---|---|---|
| 1. chain is live | pass | tip 1 -> 2 |
| 2. four PoS producers | pass | 4 producers in blocks 1..=9 |
| 3. finality advances | pass | finalized 5 -> 10 |
| 4. global header committed | pass | global header 0: 0x4c9c161b484e149c8fc2b1a19131056120a0c1d20817222f61aed055549660cc |
| 5. faucet grant | pass | alice 0x6ebea613b0e0d321cc1ed218ec7ca9532d3c63c6540a5e92afa135058a596701 holds 100000000 |
| 6. transfer and explorer | pass | transfer 714c5df153361c2d602ec0c95eb0b56c3cf631d3d74ec7156584ef6b4ec5770c landed and the explorer serves it |
| 7. delegation | pass | validator e2fcdc116e57ee1f7ab138fa823e205d2253343cfe506bd4a15b6c2eb80380fd carries 10000000 delegated |
| 8. BNS name | pass | rehearsal.bud -> 0x6ebea613b0e0d321cc1ed218ec7ca9532d3c63c6540a5e92afa135058a596701 |
| 9. Remote app binding register and pay | pass | domain 4242 registered; app_binding (mirror 0xe8c0fd1c1f0d3d1fbba39570094e14952d213a0ea17d9d942d0abe0be331b81e) contained on chain 45261 |
| 10. load | pass | 40 transfers submitted in 1094.3 s, all included after 1133.3 s: 0.04 tx/s end to end |
| 11. validator loss and rejoin | pass | finality 205 -> 225 with seat offline (tip 212 -> 231); caught up and produced block 240 |
