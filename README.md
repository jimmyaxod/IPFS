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

    The publickey is encoded as per https://github.com/libp2p/specs/blob/master/peer-ids/peer-ids.md#keys
    
    An example Propose message:
        rand: "\375\230E\025\357\245\3151\213\235\n\221\352c\037_"
        pubkey: "\b\000\022\246\0020\202\001\"0\r\006\t*\206H\206\367\r\001\001\001\005\000\003\202\001\017\0000\202\001\n\002\202\001\001\000\321!d\033\277\240z@\255\030\3752\306>\325#\276\"\330\263\331\326\2638\340\312\221j\"~\326\022\337\254\373\242\312l\310\351\275\3263\243\256V#\230\272h\034\020\253\027\342\344\357\366\256P\260\020{4\227m\241@A\035\252\031\362\226Q\tt\217\256^\364\254I\337\367\t\376\250/(\312\327b\037!\226\233\274P\223\261\341#\266\2619\370\264luyJ}\210\354g\202]\351\235\005\310wh\321\326 tM\204\227\2105\335\371\'\331W\002\0049\247w\365\264\235x\303\347S\215s\364i\0039R\334S\354\376\036\311U\352G\214v\362\001\254\211LS\030\375\237\304\016\016\233e\240C\177\030\033m\'\025\210t\302\317\226\177t\344B9G\311\341\2314\361\306\204\264&\353_<\036\362\002\303P\322\323\246\226\301K\3544%D\235\337r}\366\rB\3746\212\253A\214.+.pU\351\030jm\336HX\"4k\002\003\001\000\001"
        exchanges: "P-256,P-384,P-521"
        ciphers: "AES-256,AES-128"
        hashes: "SHA256,SHA512"
