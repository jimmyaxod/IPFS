# IPFS
Playing with IPFS

For now, this will be limited to TCP transport. I'm going to be looking at the DHT.

1. multistream
    First off, we need to handshake with multistream-select
    Messages are prefixed by message length as a varint
    https://github.com/multiformats/multistream-select/
    
    Example connection handshake
    
    A connects to B
    
    B -> A  varint(19), "/multistream/1.0.0\n"
    
    A -> B  varint(19), "/multistream/1.0.0\n"
    
    Next we tell them we'd like to use secio
    
    A -> B  varint(13), "/secio/1.0.0\n"
    
    If they agree then they'll tell us. If not, they'd send 'na' as per spec.
    
    B -> A  varint(13), "/secio/1.0.0\n"
    
    Now, we switch to using secio.
    
2. secio
    Next step is to negotiate security.
    Messages are prefixed with a 32bit length big endian
    https://github.com/libp2p/specs/tree/master/secio
    
    B -> A  int32length, data
    
    The data is a protobuff encoded 'Propose' message as per spec. This contains the public key for B, along with a list of exchanges,ciphers and hashes.

