# Protocol

## Multistream select

The multistream-select protocol is a very simple way for both sides to agree on a protocol to use for the next steps. It's used both at the start or connection to select the crypto, mux, etc. But it's also then used within each mux stream to select things like ID, DHT, BITSWAP, etc

All multistream messages are prefixed with their length, as a varint. A varint is simply a sequence of bytes, where the MSB signifies if there are more bytes or not. The lower 7 bits are combined together to form the value.

### Example multistream select

| Comment               | A                                     | B                                     |
| --------------------- | ------------------------------------- | ------------------------------------- |
| TCP connection        | Connection to B established           |                                       |
| Multistream           |                                       | varint(19), "/multistream/1.0.0\n"    |
| Multistream           | varint(19), "/multistream/1.0.0\n"    |                                       |
| Ask for secio         | varint(13), "/secio/1.0.0\n"          |                                       |
| Agree to secio        |                                       | varint(13), "/secio/1.0.0\n"          |

Alternatively, if B doesn't support the requested protocol, it can reply with 'na\n'. Then A can propose something else.
Additionally, A could send 'ls' after the Multistream, to list available protocols.

More information can be found here https://github.com/multiformats/multistream-select/

## Security

Security is pretty important, and so the first thing we must do with any libp2p connection is secure it against eavesdroppers. There are currently 3 protocols you can use to achieve this.

* TLS
* Secio https://github.com/libp2p/specs/tree/master/secio
* Noise

First, we open a connection to a host, then use multistream-select to select an encryption protocol. The example above shows us asking for secio. However, secio will soon be dropped from support. So, we must move to Noise or TLS.




To play with IPFS, we need to jump through several hoops. This is not a simple protocol like BitTorrent, or HTTP. It has several layers.

1. Security - For now, we are only going to support secio. This encrypts and signs all messages.
2. Multiplex - For now, we are only supporting yamux. This allows us to open several different 'streams' within the same connection.
3. Identify - Allows us to identify who we are communicating with, and send our info to them.
4. DHT - Finally, we get to play on the DHT.
        
## secio
    
Next step is to negotiate security.
Messages are prefixed with a 32bit length big endian
https://github.com/libp2p/specs/tree/master/secio
    
B -> A  int32length, data (Propose)
    
The data is a protobuff encoded 'Propose' message as per spec. This contains the public key for B, along with a list of exchanges,ciphers and hashes.

The publickey is encoded as per https://github.com/libp2p/specs/blob/master/peer-ids/peer-ids.md#keys
    
An example Propose message:
> rand: "\375\230E\025\357\245\3151\213\235\n\221\352c\037_"
> pubkey: "\b\000\022\246\0020\202\001\"0\r\006\t*\206H\206\367\r\001\001\001\005\000\003\202\001\017\0000\202\001\n\002\202\001\001\000\321!d\033\277\240z@\255\030\3752\306>\325#\276\"\330\263\331\326\2638\340\312\221j\"~\326\022\337\254\373\242\312l\310\351\275\3263\243\256V#\230\272h\034\020\253\027\342\344\357\366\256P\260\020{4\227m\241@A\035\252\031\362\226Q\tt\217\256^\364\254I\337\367\t\376\250/(\312\327b\037!\226\233\274P\223\261\341#\266\2619\370\264luyJ}\210\354g\202]\351\235\005\310wh\321\326 tM\204\227\2105\335\371\'\331W\002\0049\247w\365\264\235x\303\347S\215s\364i\0039R\334S\354\376\036\311U\352G\214v\362\001\254\211LS\030\375\237\304\016\016\233e\240C\177\030\033m\'\025\210t\302\317\226\177t\344B9G\311\341\2314\361\306\204\264&\353_<\036\362\002\303P\322\323\246\226\301K\3544%D\235\337r}\366\rB\3746\212\253A\214.+.pU\351\030jm\336HX\"4k\002\003\001\000\001"
> exchanges: "P-256,P-384,P-521"
> ciphers: "AES-256,AES-128"
> hashes: "SHA256,SHA512"

We need to send out our own Propose message. Generate our own random bytes, generate a public key etc.
    
A -> B  int32length, data (Propose)

Next we should receive an Exchange message.
    
B -> A  int32length, data (Exchange)
    
An example Exchange message
>    epubkey: "\004\276\331n\027!\236r\346\375E\231?2j\225~\f\"\341\301\002\262/\374)wY\016+B\345\024\224\345\200\2518gJ1V\213/\270s@@ +\371\f\300N\005|\\\216F^WJ\3278\223"
>    signature: "5\212\311\364V\241\202)\305B\036w\266ue\233\342sr\037\370\027\246)\227\336\276/\316\244\rM\351\232\313\362,<\347\255\017t\273\177\2716:>\037\221\365J\307sB\223F&\002\272\253\037\224\032\217\320\214!\207f\315\t\355\242\257!.\353\241\0368\351\001\026?2\203\005p\370=>T\305\352\020\372\232\rP\375\330\332i\211_\204z\236)\242\364h\373W\v\206\024\322\000\rG\272\277\017\016\311W\3375\t\365\366\242\202A|\363\352\2650\312\325\356\263\237\177na&\237\257\372\314%\331\216$%\254\v=Sg\002\257\016O\223+n\305\273\321\354\320&\325\373~\251J\027\204\360~\207}\004\333\217g|W\247Q\277\377\271\276\217\322bjk[\223\2306\265U\257\003\204\264\364g\354\323H;_\246J\321\342\232\320\312\032k\247&\231\255\227AO\202\245\266\3276\237y\306\'q\264\251\347f4\004\234\243"

As you can see, the Exchange message contains a signature. We should first verify this signature, and close the connection if it's not correct.
The signature is created by first preparing a corpus to sign, and then signing it using the public key.
corpus = remote_propose_bytes + local_propose_bytes + remote_exchange.epubkey
SHA256withRSA verify signature using remote_propose.pubkey
    
If this signature verifies, then we can continue...
    
Next step we need to generate our own Exchange message.
    
First we generate an EC Keypair using the agreed upon exchange (In the example above P-256).
The public key from this is used as local_exchange.epubkey
    
corpus = local_propose_bytes + remote_propose_bytes + local_exchange.epubkey
signature = SHA256withRSA sign using local_propose.pubkey
    
| Comment               | A                                     | B                                     |
| --------------------- | ------------------------------------- | ------------------------------------- |
|                       |                                       | Propose message                       |
|                       | Propose message                       |                                       |
|                       |                                       | Exchange message                      |
|                       | Exchange message                      |                                       |

Once this is completed, if you have done everything correctly, you will receive a new message from B, which contains the nonce (random bytes) from the Propose message, encrypted and signed using new keys.
    
These keys have to be created from the above...
    
TODO: Document shared secret and key stretching

TODO: Document Yamux multiplexing

TODO: Document ipfs/id Identify messaging

TODO: Document kad DHT messaging
