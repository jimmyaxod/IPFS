package net.axod.ipfscrawl;

import net.axod.*;
import net.axod.io.*;
import net.axod.protocols.*;

import net.axod.util.*;

import com.google.protobuf.*;

import io.ipfs.multihash.*;

import java.net.*;
import java.nio.*;
import java.util.*;
import java.security.*;
import java.math.*;
import java.security.spec.*;
import java.security.interfaces.*;
import java.util.logging.*;

/**
 * This represents a connection to an IPFS node.
 *
 * We need to jump through several hoops before we can get to the interesting
 * bits.
 *
 *
 *
 */
public class IPFSIOPlugin extends IOPlugin {
    private static Logger logger = Logger.getLogger("net.axod.ipfscrawl");

    // Initial multistream handshake
	boolean handshaked = false;
	
	// Have we got propose / exchange messages yet?
	boolean got_propose = false;
	boolean got_exchange = false;

	// We store the incoming and outgoing propose / exchange packets
	SecioProtos.Propose local_propose = null;
	SecioProtos.Propose remote_propose = null;
	SecioProtos.Exchange local_exchange = null;
	SecioProtos.Exchange remote_exchange = null;

	// My RSA keys
	KeyPair mykeys = null;
	
	// The EC keys
	KeyPair ec_keys = null;

	/**
	 * Given a public key, we can get a Multihash which shows the PeerID in a
	 * more usable format.
	 *
	 */
	public Multihash getPeerID(byte[] pubkey) {
		Multihash h;

		// Let's work out their ID...
		if (pubkey.length<=42) {
			// Use identity multihash
			h = new Multihash(Multihash.Type.id, pubkey);
		} else {
			// Use sha2-256
			try {
				MessageDigest md = MessageDigest.getInstance("SHA-256");
				md.update(pubkey);
				byte[] digest = md.digest();
				h = new Multihash(Multihash.Type.sha2_256, digest);
				
			} catch (NoSuchAlgorithmException e) {
				throw new RuntimeException(e.getMessage(), e);
			}								
		}
		return h;
	}

	/**
	 * Create a new plugin to handle a connection.
	 *
	 */
	public IPFSIOPlugin(Node n, InetSocketAddress isa) {
        in.order(ByteOrder.BIG_ENDIAN);
        out.order(ByteOrder.BIG_ENDIAN);

        // TODO: Allow reusing previous keys. These should be stored and reused.
        try {
        	KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        	SecureRandom random = SecureRandom.getInstance("SHA1PRNG");

        	keyGen.initialize(2048, random);

        	mykeys = keyGen.generateKeyPair();

        } catch(Exception e) {
        	logger.warning("Can't generate keys!");	
        }
	}

	/**
	 * Does the plugin need to send anything
	 */
	public boolean wantsToWork() {
		return false;	
	}

	/**
	 * Write a multistream message, using varint framing.
	 *
	 */
	private void writeMultistream(String d) {
		byte[] data = d.getBytes();
		writeVarInt(data.length);
		out.put(data);
	}
	
	/**
	 * Write a varint out
	 *
	 */
	private void writeVarInt(long v) {
		while(true) {
			byte d = (byte)(v & 0x7f);
			if (v>0x80) {
				d = (byte) (d | 0x80);	// Signal there's more to come...
				out.put(d);
			} else {
				out.put(d);
				break;
			}
			v = v >> 7;
		}
	}

	/**
	 * Read a varint
	 *
	 */
	private long readVarInt() throws BufferUnderflowException {
		long len = 0;
		int sh = 0;
		while(true) {
			int b = ((int)in.get()) & 0xff;
			long v = (b & 0x7f);
			len = len | (v << sh);
			if ((b & 0x80)==0) break;
			sh+=7;
		}
		return len;			
	}
	
	/**
	 * Main work method.
	 *
	 */
	public void work() {
		logger.fine("Work " + in);
		
		if (in.position()>0) {
			if (!handshaked) {
				// We haven't performed the multistream handshake yet, so we should
				// do that now.
				in.flip();
				
				// Try to read a complete packet. If we can't we abort.
				
				try {
					int len = (int)readVarInt();
					byte[] data = new byte[len];
					in.get(data);
					String l = new String(data);
					logger.info("Multistream handshake (" + l.trim() + ")");

					// For now, we only support multistream/1.0.0
					if (l.equals("/multistream/1.0.0\n")) {
						// OK, as expected, lets reply and progress...
						writeMultistream("/multistream/1.0.0\n");						
						writeMultistream("/secio/1.0.0\n");
						
					// For now, we only support secio/1.0.0
					} else if (l.equals("/secio/1.0.0\n")) {
						// OK, need to move on to next stage now...
						handshaked = true;
					}
				} catch(Exception e) {
					logger.warning("Issue reading... " + e);
					in.rewind();	// Unread it all... We'll try again later...	
				}
				in.compact();
			}
			
			// Now lets do SECIO
			if (handshaked) {
				in.flip();
				while(in.remaining()>0) {
					try {
						int len = in.getInt();		// Length is 32bit int
						if (len>8000000) {
							logger.warning("Got a packet of >8MB?");
							break;
						}
						byte[] data = new byte[len];
						in.get(data);
						
						if (!got_propose) {							
							remote_propose = SecioProtos.Propose.parseFrom(data);
	
							logger.info("Secio remote propose\n" + remote_propose + "\n");
	
							byte[] pubkey = remote_propose.getPubkey().toByteArray();
							PeerKeyProtos.PublicKey pk = PeerKeyProtos.PublicKey.parseFrom(pubkey);
							logger.info("Secio remote peerID " + getPeerID(pubkey));

							// Create our own PROPOSE
							byte[] orand = new byte[16];
							for(int i=0;i<orand.length;i++) {
								orand[i] = (byte) (Math.random() * 256);	
							}

        					PeerKeyProtos.PublicKey mpk = PeerKeyProtos.PublicKey.newBuilder()
        												 .setType(PeerKeyProtos.KeyType.RSA)
        												 .setData(ByteString.copyFrom(mykeys.getPublic().getEncoded()))
        												 .build();
        					
        					logger.info("Secio local peerID " + getPeerID(mykeys.getPublic().getEncoded()));

							byte[] opubkey = mpk.toByteArray();
							String oexchanges = remote_propose.getExchanges();
							String ociphers = remote_propose.getCiphers();
							String ohashes = remote_propose.getHashes();
							
							// Lets create our own...
							local_propose = SecioProtos.Propose.newBuilder()
													  .setRand(ByteString.copyFrom(orand))
													  .setPubkey(ByteString.copyFrom(opubkey))
													  .setExchanges(oexchanges)
													  .setCiphers(ociphers)
													  .setHashes(ohashes)
													  .build();
							
							byte[] odata = local_propose.toByteArray();
	
							logger.info("Secio local propose\n" + local_propose);							
							out.putInt(odata.length);
							out.put(odata);

							got_propose = true;
						} else if (!got_exchange) {
							// Now we're expecting an Exchange...
							remote_exchange = SecioProtos.Exchange.parseFrom(data);

							logger.info("Secio remote exchange\n" + remote_exchange + "\n");

							// TODO: We should do all the check to see who is who, and
							// then decide which cyphers win etc.
							//
							// For now, we'll just assume p-256

							try {
								byte[] pubkey = remote_propose.getPubkey().toByteArray();
								PeerKeyProtos.PublicKey pk = PeerKeyProtos.PublicKey.parseFrom(pubkey);
								
								byte[] keybytes = pk.getData().toByteArray();		
								PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(keybytes));
								System.out.println("Remote publickey " + publicKey);
						
								boolean verified = SecioHelper.checkSignature(publicKey, local_propose.toByteArray(), remote_propose.toByteArray(), remote_exchange);

								System.out.println("Secio remote checking signature... [" + (verified?"correct":"incorrect") + "]");
								if (!verified) {
									close();
									return;
								}
							} catch(Exception ve) {
								logger.warning("Can't verify " + ve);	
								ve.printStackTrace();
								close();
								return;
							}

							// First we need to create EC keypair
							// Second we need to create a signature
							ec_keys = SecioHelper.createECKeypair();
							
							// Encode the pubkey as required...
							byte[] ec_pubkey = SecioHelper.getECPublicKey(ec_keys);
							
							// Now create the signature...
							byte[] signature = SecioHelper.sign(mykeys.getPrivate(), local_propose.toByteArray(), remote_propose.toByteArray(), ec_pubkey);
							
							// TODO: Send out our exchange...
							local_exchange = SecioProtos.Exchange.newBuilder()
											.setEpubkey(ByteString.copyFrom(ec_pubkey))
											.setSignature(ByteString.copyFrom(signature))
											.build();

							byte[] odata = local_exchange.toByteArray();
	
							logger.info("Secio local exchange\n" + local_exchange);							
							out.putInt(odata.length);
							out.put(odata);
							
							got_exchange = true;
							
							// TODO: Create shared secret
														
							// x,y are from THEIR_PUB
							// priv is our private key
							//
							// ScalarMult returns k*(Bx,By) where k is a number in big-endian form.
							// ScalarMult(x1, y1 *big.Int, k []byte) (x, y *big.Int)
							//
							// Generate shared secret.
							// secret, _ := curve.ScalarMult(x, y, priv)

							
							
							// TODO: Key stretching
							
						} else {
							
							
							System.out.println("Secio DATA " + data.length);
							showHexData(data);


						}
					} catch(BufferUnderflowException bue) {
						// Don't have the data yet...
						in.rewind();	// 'Unread' any partial packet
						break;
					} catch(Exception e) {
						logger.warning("Exception " + e);
						e.printStackTrace();
						close();
						break;
					}
					// Get rid of this packet, and move on to the next...
					in.compact();
					in.flip();
				}
				in.compact();
			}
		}
	}
	
	public void closing() {
		logger.info("Connection closing...");
	}
	
	private static void showHexData(byte[] d) {
		int o = 0;
		while(true) {
			String l = "";
			for(int i=0;i<Math.min(16, d.length - o); i++) {
				String ch = "00" + Integer.toString(((int)d[o+i]) & 0xff, 16);
				ch = ch.substring(ch.length() - 2, ch.length());
				l += " " + ch;
			}
			System.out.println(" " + l);
			o+=16;
			if (o>=d.length) break;
		}
	}
	
}