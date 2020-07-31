package net.axod.protocols;

import com.google.protobuf.*;

import net.axod.*;

import java.nio.*;
import java.util.*;
import java.security.*;
import java.security.spec.*;
import java.security.interfaces.*;

public class SecioHelper {

	static SecioProtos.Propose local_propose;
	static SecioProtos.Propose remote_propose;
	static SecioProtos.Exchange local_exchange;
	static SecioProtos.Exchange remote_exchange;

	/**
	 * Verify a signature...
	 *
	 */
	public static boolean checkSignature(PublicKey pk, byte[] local_propose_bytes, byte[] remote_propose_bytes, SecioProtos.Exchange exchange) throws Exception {
		byte[] epubkey = exchange.getEpubkey().toByteArray();
		
		// Create the corpus
		byte[] corpus = new byte[local_propose_bytes.length + remote_propose_bytes.length + epubkey.length];
		ByteBuffer bb = ByteBuffer.allocate(corpus.length);
		bb.put(remote_propose_bytes);
		bb.put(local_propose_bytes);
		bb.put(epubkey);
		bb.flip();
		bb.get(corpus);

		byte[] signature = exchange.getSignature().toByteArray();
		
		// TODO: Do we need to support others?
		Signature verify = Signature.getInstance("SHA256withRSA");

		verify.initVerify(pk);
		verify.update(corpus);
		return verify.verify(signature);		
	}

	/**
	 * Create a signature...
	 *
	 */
	public static byte[] sign(PrivateKey pk, byte[] local_propose_bytes, byte[] remote_propose_bytes, byte[] epubkey) throws Exception {
		
		// Create the corpus
		byte[] corpus = new byte[remote_propose_bytes.length + local_propose_bytes.length + epubkey.length];
		ByteBuffer bb = ByteBuffer.allocate(corpus.length);
		bb.put(local_propose_bytes);
		bb.put(remote_propose_bytes);
		bb.put(epubkey);
		bb.flip();
		bb.get(corpus);

		// TODO: Do we need to support others?
		Signature sign = Signature.getInstance("SHA256withRSA");

		sign.initSign(pk);
		sign.update(corpus);
		return sign.sign();		
	}
	
	/**
	 * Converts an uncompressed secp256r1 / P-256 public point to the EC public key it is representing.
	 * @param w a 64 byte uncompressed EC point starting with <code>04</code>
	 * @return an <code>ECPublicKey</code> that the point represents 
	 */
	public static ECPublicKey generateP256PublicKeyFromUncompressedW(byte[] w) throws InvalidKeySpecException {
		if (w[0] != 0x04) {
			throw new InvalidKeySpecException("w is not an uncompressed key");
		}
		return generateP256PublicKeyFromFlatW(Arrays.copyOfRange(w, 1, w.length));
	}
	
	private static byte[] P256_HEAD = Base64.getDecoder().decode("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE");
	//MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE		// 36 characters in base64
	//MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEBnW6EfMLgy0/pPiL2xSwD3ygbmNI6eNtf/dsxPzpAUuoCTVs469GcJaWnV9WMkBcEfJcL9GpBihQ7qiR+n5uPw==
	
	/**
	 * Converts an uncompressed secp256r1 / P-256 public point to the EC public key it is representing.
	 * @param w a 64 byte uncompressed EC point consisting of just a 256-bit X and Y
	 * @return an <code>ECPublicKey</code> that the point represents 
	 */
	public static ECPublicKey generateP256PublicKeyFromFlatW(byte[] w) throws InvalidKeySpecException {
		byte[] encodedKey = new byte[P256_HEAD.length + w.length];
		System.arraycopy(P256_HEAD, 0, encodedKey, 0, P256_HEAD.length);
		System.arraycopy(w, 0, encodedKey, P256_HEAD.length, w.length);
		KeyFactory eckf;
		try {
			eckf = KeyFactory.getInstance("EC");
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("EC key factory not present in runtime");
		}
		X509EncodedKeySpec ecpks = new X509EncodedKeySpec(encodedKey);
		return (ECPublicKey) eckf.generatePublic(ecpks);
	}
	
	public static KeyPair createECKeypair() throws Exception {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");

        keyGen.initialize(256, random);

        KeyPair pair = keyGen.generateKeyPair();
        PrivateKey priv = pair.getPrivate();
        PublicKey pub = pair.getPublic();

        System.out.println(priv);
        System.out.println(pub);

        // Get bytes for pub so we can send...
        byte[] pubk = pub.getEncoded();
        String pubkeyenc = Base64.getEncoder().encodeToString(pubk);

        System.out.println("Public Key encoded len " + pubk.length);
        System.out.println("KEY " + pubkeyenc);

        // Try extracting what we need to go into the packet...
		byte[] encodedKey = new byte[64];
		System.arraycopy(pubk, pubk.length - 64, encodedKey, 0, 64);

		// Now we have 64 bytes
		ECPublicKey tryk = generateP256PublicKeyFromFlatW(encodedKey);

		System.out.println(tryk);
		System.out.println(Base64.getEncoder().encodeToString(tryk.getEncoded()));
        
        return pair;
	}
	
	public static byte[] getECPublicKey(KeyPair kp) {
        // Get bytes for pub so we can send...
        byte[] pubk = kp.getPublic().getEncoded();
        String pubkeyenc = Base64.getEncoder().encodeToString(pubk);

        // Try extracting what we need to go into the packet...
		byte[] encodedKey = new byte[65];
		encodedKey[0] = 4;
		System.arraycopy(pubk, pubk.length - 64, encodedKey, 1, 64);
		return encodedKey;		
	}
	
	public static void main(String[] args) {
		try {
		System.out.println("Going to test verify");	

		byte[] remote_propose_bytes = {10,16,-108,-53,80,113,-101,-68,-52,-54,41,-51,81,43,-54,93,-70,-92,18,-85,2,8,0,18,-90,2,48,-126,1,34,48,13,6,9,42,-122,72,-122,-9,13,1,1,1,5,0,3,-126,1,15,0,48,-126,1,10,2,-126,1,1,0,-47,33,100,27,-65,-96,122,64,-83,24,-3,50,-58,62,-43,35,-66,34,-40,-77,-39,-42,-77,56,-32,-54,-111,106,34,126,-42,18,-33,-84,-5,-94,-54,108,-56,-23,-67,-42,51,-93,-82,86,35,-104,-70,104,28,16,-85,23,-30,-28,-17,-10,-82,80,-80,16,123,52,-105,109,-95,64,65,29,-86,25,-14,-106,81,9,116,-113,-82,94,-12,-84,73,-33,-9,9,-2,-88,47,40,-54,-41,98,31,33,-106,-101,-68,80,-109,-79,-31,35,-74,-79,57,-8,-76,108,117,121,74,125,-120,-20,103,-126,93,-23,-99,5,-56,119,104,-47,-42,32,116,77,-124,-105,-120,53,-35,-7,39,-39,87,2,4,57,-89,119,-11,-76,-99,120,-61,-25,83,-115,115,-12,105,3,57,82,-36,83,-20,-2,30,-55,85,-22,71,-116,118,-14,1,-84,-119,76,83,24,-3,-97,-60,14,14,-101,101,-96,67,127,24,27,109,39,21,-120,116,-62,-49,-106,127,116,-28,66,57,71,-55,-31,-103,52,-15,-58,-124,-76,38,-21,95,60,30,-14,2,-61,80,-46,-45,-90,-106,-63,75,-20,52,37,68,-99,-33,114,125,-10,13,66,-4,54,-118,-85,65,-116,46,43,46,112,85,-23,24,106,109,-34,72,88,34,52,107,2,3,1,0,1,26,17,80,45,50,53,54,44,80,45,51,56,52,44,80,45,53,50,49,34,15,65,69,83,45,50,53,54,44,65,69,83,45,49,50,56,42,13,83,72,65,50,53,54,44,83,72,65,53,49,50};
		byte[] local_propose_bytes = {10,16,-86,-94,-102,-20,120,-102,29,28,50,-51,114,-52,13,18,-18,-55,18,-85,2,8,0,18,-90,2,48,-126,1,34,48,13,6,9,42,-122,72,-122,-9,13,1,1,1,5,0,3,-126,1,15,0,48,-126,1,10,2,-126,1,1,0,-47,33,100,27,-65,-96,122,64,-83,24,-3,50,-58,62,-43,35,-66,34,-40,-77,-39,-42,-77,56,-32,-54,-111,106,34,126,-42,18,-33,-84,-5,-94,-54,108,-56,-23,-67,-42,51,-93,-82,86,35,-104,-70,104,28,16,-85,23,-30,-28,-17,-10,-82,80,-80,16,123,52,-105,109,-95,64,65,29,-86,25,-14,-106,81,9,116,-113,-82,94,-12,-84,73,-33,-9,9,-2,-88,47,40,-54,-41,98,31,33,-106,-101,-68,80,-109,-79,-31,35,-74,-79,57,-8,-76,108,117,121,74,125,-120,-20,103,-126,93,-23,-99,5,-56,119,104,-47,-42,32,116,77,-124,-105,-120,53,-35,-7,39,-39,87,2,4,57,-89,119,-11,-76,-99,120,-61,-25,83,-115,115,-12,105,3,57,82,-36,83,-20,-2,30,-55,85,-22,71,-116,118,-14,1,-84,-119,76,83,24,-3,-97,-60,14,14,-101,101,-96,67,127,24,27,109,39,21,-120,116,-62,-49,-106,127,116,-28,66,57,71,-55,-31,-103,52,-15,-58,-124,-76,38,-21,95,60,30,-14,2,-61,80,-46,-45,-90,-106,-63,75,-20,52,37,68,-99,-33,114,125,-10,13,66,-4,54,-118,-85,65,-116,46,43,46,112,85,-23,24,106,109,-34,72,88,34,52,107,2,3,1,0,1,26,17,80,45,50,53,54,44,80,45,51,56,52,44,80,45,53,50,49,34,15,65,69,83,45,50,53,54,44,65,69,83,45,49,50,56,42,13,83,72,65,50,53,54,44,83,72,65,53,49,50};
		byte[] remote_exchange_bytes = {10,65,4,4,-5,-54,-84,89,-13,31,-22,-15,72,122,26,-114,-65,-2,34,57,99,-123,35,-65,35,90,31,-36,112,3,-105,-79,-122,4,-24,11,31,-14,85,101,123,33,-15,-115,-19,0,-44,-107,19,-16,-36,91,-8,-76,-111,-107,-89,-65,-41,35,45,45,76,108,78,98,-102,18,-128,2,80,-25,-38,99,-106,96,-102,-84,66,-20,-54,-74,118,-60,123,-24,-81,84,-87,-15,-94,-43,10,-39,19,-69,31,-34,0,-126,-66,55,-37,-93,7,-50,-21,95,93,25,-26,-81,24,-18,44,-102,-59,-54,-50,25,119,-124,-51,-54,55,24,108,-6,-61,13,-67,60,-44,96,-113,-58,18,-33,-115,-108,-27,29,-64,-48,108,-122,-36,-29,-75,111,-76,-120,121,-117,-45,-106,69,10,82,-117,-50,80,20,-36,82,110,-15,18,-84,-95,46,-22,-20,-16,110,1,-120,30,65,-103,14,55,-124,97,-16,-88,-127,9,91,-21,-29,30,6,108,5,-25,-7,101,-123,-57,-51,49,5,-10,93,13,80,116,52,-69,33,104,-67,-55,124,-116,54,31,-36,-8,50,8,56,-12,-49,17,20,116,-80,126,124,110,-77,93,-105,-96,-119,63,33,-6,-21,-53,-90,124,0,22,-54,-21,8,-53,-41,28,-63,-36,45,66,56,106,-76,-115,120,0,-69,-74,-5,-2,-75,58,-97,41,-59,-123,-47,75,-103,107,64,-68,-12,58,-47,40,66,17,-77,-100,-90,27,3,-109,-86,93,92,-128,-71,82,123,90,13,-48,37,63,-72,-119,16,-24,-53,-110,116,110,-96,43,-70,7,-24,-21,-119,125,-92,-64,11,-35,-126,-94,-15,79};

		local_propose = SecioProtos.Propose.parseFrom(local_propose_bytes);
		remote_propose = SecioProtos.Propose.parseFrom(remote_propose_bytes);
		remote_exchange = SecioProtos.Exchange.parseFrom(remote_exchange_bytes);

		System.out.println("LOCAL " + local_propose);

		System.out.println("REMOTE " + remote_propose);

		System.out.println("REMOTE " + remote_exchange);

		byte[] pubkey = remote_propose.getPubkey().toByteArray();
		PeerKeyProtos.PublicKey pk = PeerKeyProtos.PublicKey.parseFrom(pubkey);
		System.out.println("KEY " + pk);

		byte[] keybytes = pk.getData().toByteArray();		
		System.out.println("RSA KEY BYTES " + keybytes.length);
		PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(keybytes));
		System.out.println("Remote publickey " + publicKey);

		boolean verified = checkSignature(publicKey, local_propose_bytes, remote_propose_bytes, remote_exchange);

		System.out.println("Signed? " + verified);

		System.out.println("\n\nNow lets create our own signature...");
		KeyPair keys = createECKeypair();
		
		
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");

        keyGen.initialize(2048, random);

        KeyPair pair = keyGen.generateKeyPair();
        PrivateKey priv = pair.getPrivate();
        PublicKey pub = pair.getPublic();
        
        System.out.println("Created RSA keypair: " + pair);
        byte[] mypubkey = pub.getEncoded();
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(mypubkey);
        byte[] mypubkey2 = x509EncodedKeySpec.getEncoded();
        System.out.println("Mypubkey " + mypubkey.length + " " + mypubkey2.length);
        
        /*
        // Store Public Key.
 X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(
   publicKey.getEncoded());
 publicKeyOutput.write(x509EncodedKeySpec.getEncoded());
 // Store Private Key.
 PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
   privateKey.getEncoded());
 privateKeyOutput.write(pkcs8EncodedKeySpec.getEncoded());
 		*/
        

		} catch(Exception e) {
			System.out.println("Exception " + e);	
		}
	}
	
}