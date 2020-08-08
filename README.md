# IPFS
Playing with IPFS

For now, this will be limited to TCP transport. I'm going to be looking at the DHT.

* multistream_select (Working)
* Secio (Working) [RSA, ECDSA, Ed25519] TODO Secp256k1
* Yamux multiplexing (Working, needs formalizing)
* Crawling the DHT by random walk (Working)
* Listening for requests by operating in 'server' mode on the DHT (TODO)
* Incoming TCP connections (Started)
* BITSWAP, circuit relay etc

Aims
 * Insight into who is using IPFS, geography, orgs, etc
 * Network performance. Monitor latency, connectivity, uptime, average query time, etc
 * Insight into what content is being shared, individual volumes by hash.
 * Monitor nefarious use of the network - bot control channel eg 'Storm'

Comparison with BitTorrent DHT

BitTorrent DHT Query - 2 packets (1 out, 1 in)

| out |  in | Description        |
| --- | --- | ------------------ |
|   1 |     | FIND_NODE query    |
|     |   1 | FIND_NODE response |

IPFS DHT Query - 17 packets (9 out, 8 in)

| out |  in | Description                        |
| --- | --- | ---------------------------------- |
|   1 |     | TCP SYN                            |
|     |   1 | TCP SYN/ACK                        |
|   1 |     | TCP ACK                            |
|   1 |     | Multistream_select (secio)         |
|     |   1 | Multistream_accept (secio)         |
|   1 |     | Secio PROPOSE                      |
|     |   1 | Secio PROPOSE                      |
|   1 |     | Secio EXCHANGE                     |
|     |   1 | Secio EXCHANGE                     |
|   1 |     | Secio encoded nonce                |
|     |   1 | Secio encoded nonce                |
|   1 |     | Multistream_select (yamux)         |
|     |   1 | Multistream_accept (yamux)         |
|   1 |     | Yamux Multistream_select (kad dht) |
|     |   1 | Yamux Multistream_accept (kad dht) |
|   1 |     | DHT FIND_NODE query                |
|     |   1 | DHT FIND_NODE response             |


Top versions from a crawl

| Count | Version ID                 |
| ----- | -------------------------- |
|  2193 | storm                      |
|  1324 | go-ipfs/0.4.22/            |
|  1306 | go-ipfs/0.4.20/            |
|   475 | hydra-booster/0.4.3        |
|   315 | go-ipfs/0.6.0/             |
|   217 | go-ipfs/0.4.23/            |
|   169 | dhtbooster/2               |
|   156 | go-ipfs/0.5.1/             |
|   131 | go-ipfs/0.4.21/            |
|   115 | go-ipfs/0.6.0/d6e036a      |


Incoming Yamux protocol negotiations (TODO)

| count | protocol                   |
| ----- | -------------------------- |
|     5 | /floodsub/1.0.0            |
|     9 | /ipfs/bitswap/1.1.0        |
|     4 | /ipfs/bitswap/1.2.0        |
|   637 | /ipfs/id/1.0.0             |
|   103 | /ipfs/kad/1.0.0            |
|   101 | /libp2p/circuit/relay/0.1.0 |
|     2 | /meshsub/1.0.0             |

