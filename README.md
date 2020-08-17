# IPFS
Playing with IPFS and libp2p

## Aims
* Insight into who is using IPFS, geography, orgs, etc. ipv4 vs ipv6, tcp vs quic, different versions, etc
* Network performance, latency, etc. How much slower than say bittorrent DHT. Node churn, etc
* General health of the network. Look at node uptime, size of network, etc
* Nefarious use of the network - bot control channel eg 'Storm'.
* Implement and maintain libp2p in Java
* Insight into what content is being shared, search engine, popularity metrics, etc


For now, this will be limited to TCP transport. I'm going to be looking at the DHT.

* multistream_select (Working)
* Secio (Working) [RSA, ECDSA, Ed25519] TODO Secp256k1
* Yamux multiplexing (Working, needs formalizing)
* Crawling the DHT by random walk (Working)
* Parsing and logging BITSWAP messages (working)
* Incoming TCP connections (working)
* Listening for requests by operating in 'server' mode on the DHT (TODO)
* circuit relay etc
* Noise (TODO)

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

[Protocol information can be found here](Protocol.md)

[Crawl statistics](crawl_stats.md)


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

