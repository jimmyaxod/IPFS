package net.axod.crypto;

import net.axod.*;
import net.axod.protocols.*;

import com.google.protobuf.*;

import io.ipfs.multihash.*;

import java.security.*;
import java.security.spec.*;


/**
 * A Secio session handles SECIO
 *
 *
 *
 */
public class SecioSession {

	public boolean we_are_primary = true;
	
	public SecioProtos.Propose local_propose = null;
	public SecioProtos.Propose remote_propose = null;
	public SecioProtos.Exchange local_exchange = null;
	public SecioProtos.Exchange remote_exchange = null;

	/**
	 *
	 * Create a new session
	 */
	public SecioSession() {
		
	}
	
	/**
	 * This decides who is in charge.
	 *
	 */
	public void decideOrder() {
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			md.update(remote_propose.getPubkey().toByteArray());
			md.update(local_propose.getRand().toByteArray());
			byte[] oh1 = md.digest();
			Multihash h1 = new Multihash(Multihash.Type.sha2_256, oh1);
			
			md.reset();
			md.update(local_propose.getPubkey().toByteArray());
			md.update(remote_propose.getRand().toByteArray());
			byte[] oh2 = md.digest();
			Multihash h2 = new Multihash(Multihash.Type.sha2_256, oh2);
			
			String hash1 = h1.toString();
			String hash2 = h2.toString();
			
			for(int i=0;i<hash1.length();i++) {
				char c1 = hash1.charAt(i);
				char c2 = hash2.charAt(i);
				if (c1==c2) {
					// Carry on...
				} else if (c1<c2) {
					we_are_primary = false;
					break;
				} else if (c1>c2) {
					we_are_primary = true;
					break;
				}
			}	
		} catch(java.security.NoSuchAlgorithmException nae) {
			System.err.println("java.security.NoSuchAlgorithmException");
			System.exit(-1);	
		}
	}
	
	public void createLocalPropose(byte[] publickey, String exchanges, String ciphers, String hashes) {
		// Create our own random nonce...
		byte[] orand = new byte[16];
		for(int i=0;i<orand.length;i++) {
			orand[i] = (byte) (Math.random() * 256);	
		}

		PeerKeyProtos.PublicKey mpk = PeerKeyProtos.PublicKey.newBuilder()
									 .setType(PeerKeyProtos.KeyType.RSA)
									 .setData(ByteString.copyFrom(publickey))
									 .build();

		byte[] opubkey = mpk.toByteArray();

		// Lets create our own...
		local_propose = SecioProtos.Propose.newBuilder()
								  .setRand(ByteString.copyFrom(orand))
								  .setPubkey(ByteString.copyFrom(opubkey))
								  .setExchanges(exchanges)
								  .setCiphers(ciphers)
								  .setHashes(hashes)
								  .build();
	}
	
	public boolean checkSignature() throws Exception {
		byte[] pubkey = remote_propose.getPubkey().toByteArray();
		PeerKeyProtos.PublicKey pka = PeerKeyProtos.PublicKey.parseFrom(pubkey);
		
		// TODO: Make sure it's an RSA key...
		
		byte[] keybytes = pka.getData().toByteArray();		
		PublicKey pk = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(keybytes));

		// TODO: Do we need to support others?
		Signature verify = Signature.getInstance("SHA256withRSA");
		verify.initVerify(pk);
		verify.update(remote_propose.toByteArray());
		verify.update(local_propose.toByteArray());
		verify.update(remote_exchange.getEpubkey().toByteArray());
		return verify.verify(remote_exchange.getSignature().toByteArray());		
	}
}