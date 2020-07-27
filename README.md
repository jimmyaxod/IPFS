# IPFS
Playing with IPFS

For now, this will be limited to TCP transport. I'm going to be looking at the DHT.

1. multistream
    First off, we need to handshake with multistream-select
    Messages are prefixed by message length as a varint
    https://github.com/multiformats/multistream-select/
    
2. secio
    Next step is to negotiate security.
    https://github.com/libp2p/specs/tree/master/secio
    
