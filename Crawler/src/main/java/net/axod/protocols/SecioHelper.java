package net.axod.protocols;

import com.google.protobuf.*;

import net.axod.*;

import java.nio.*;
import java.util.*;
import java.security.*;
import java.security.spec.*;
import java.security.interfaces.*;

import javax.crypto.*;
import javax.crypto.spec.*;


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

	public static void testVerify() {
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

	public static byte[][] splitStretchedKeys(byte[] data, String cipher, String hasher) {
		int iv_size = 16;
		int key_size = 16;		// AES-128 is 16, AES-256 is 32
		if (cipher.equals("AES-128")) key_size = 16;
		if (cipher.equals("AES-256")) key_size = 32;
		int mac_size = 20;

		int offset = 0;
		byte[] iv1 = new byte[iv_size];
		System.arraycopy(data, offset, iv1, 0, iv_size);
		offset+=iv_size;
		byte[] key1 = new byte[key_size];
		System.arraycopy(data, offset, key1, 0, key_size);
		offset+=key_size;
		byte[] mac1 = new byte[mac_size];
		System.arraycopy(data, offset, mac1, 0, mac_size);
		offset+=mac_size;
		
		byte[] iv2 = new byte[iv_size];
		System.arraycopy(data, offset, iv2, 0, iv_size);
		offset+=iv_size;
		byte[] key2 = new byte[key_size];
		System.arraycopy(data, offset, key2, 0, key_size);
		offset+=key_size;
		byte[] mac2 = new byte[mac_size];
		System.arraycopy(data, offset, mac2, 0, mac_size);
		offset+=mac_size;
		
		byte[][] rr = new byte[6][];
		rr[0] = iv1;
		rr[1] = key1;
		rr[2] = mac1;
		rr[3] = iv2;
		rr[4] = key2;
		rr[5] = mac2;
		
		return rr;
	}

	public static byte[] stretchKeys(byte[] ss, String cipher, String hasher) {
		// For now, let's assume we're using AES-256 and SHA256
		// Cipher key size 32
		// IV size 16
		// Mac key 20
		
		int iv_size = 16;
		int key_size = 16;		// AES-128 is 16, AES-256 is 32
		if (cipher.equals("AES-128")) key_size = 16;
		if (cipher.equals("AES-256")) key_size = 32;
		int mac_size = 20;

		byte[] seed = "key expansion".getBytes();
		
		byte[] keydata = new byte[(iv_size + key_size + mac_size) * 2];

		// Need to strip off any leading 0s, because of stupid go.
		int offset = 0;
		while(offset<ss.length && ss[offset]==0) offset++;
		byte[] ss_z = new byte[ss.length - offset];
		System.arraycopy(ss, offset, ss_z, 0, ss_z.length);
		
		try {
			Mac sha_HMAC = Mac.getInstance("Hmac" + hasher);
			SecretKeySpec secret_key = new SecretKeySpec(ss_z, "Hmac" + hasher);
			sha_HMAC.init(secret_key);
			byte[] idig = sha_HMAC.doFinal(seed);
				
			// Now go through...
			int j = 0;
			while(j<keydata.length) {
				sha_HMAC.init(secret_key);
				sha_HMAC.update(idig);
				byte[] idigb = sha_HMAC.doFinal(seed);

				// Write it out and continue...
				int todo = idigb.length;
				if (j + todo > keydata.length) {
					todo = keydata.length - j;	
				}
				System.arraycopy(idigb, 0, keydata, j, todo);
				j+=todo;
				// Now update idig...
				sha_HMAC.init(secret_key);
				idig = sha_HMAC.doFinal(idig);
			}
		} catch (Exception e) {
			throw new RuntimeException(e.getMessage(), e);
		}								
		return keydata;		
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

	public static String toHexString(byte[] d) {
		String o = "";
		for(int i=0;i<d.length;i++) {
			String ch = "00" + Integer.toString(((int)d[i]) & 0xff, 16);
			ch = ch.substring(ch.length() - 2, ch.length());
			o=o+ch;
		}
		return o;
	}
	
	public static byte[] fromHexString(String d) {
		byte[] o = new byte[d.length() / 2];
		for(int i=0;i<o.length;i++) {
			o[i] = (byte)Integer.parseInt(d.substring(i*2, i*2 + 2), 16);
		}
		return o;
	}
	
	static String[] secrets = {"4F13360145891C202B74FDCA838A85A37CBAEBF5E0774CC344BD6DABA9C4C86A",
    					"4ED31DA5EEA36277CA9E1C198F3EBB89AE4A6B18B76E48CAE8AEC23A7D0D4E8F700D6696AB01365278E5C45C2B4B1807",
    					"01D4FBB5104F9B8DEDA95B447C1401A35F995B6BEFE20DBEFF9F7A13B7DA2831FB5A7EA194C4CE1ECE340B993C4C2C53FE641227DB7428B62BF4083686F6FF8FBE8C",
    // Edge case (where Go implementation returns 65 bytes of secret)
    // Nim implementation has leading `00`.
    					"00691BB84462F460D603B3F5FA0031D8DE195234C65B8890CBB6F84456E9718D4572749FC6040D0602698EEE6CCF6FB83101A26925D1A3AB40FB45BF98EAF06A2693",
    // AES-256 SHA-512
    					"1F29EC3E0A07994D2ACCEA23A2F570DA9C7A7E39D5026FE6340C1E551E1ADAAF",
    					"85C20386C1EA1575DD8D111111DBC8B43CA630BEE4BB9AD91658719FF307C0BE0065935B8B849BE80E0D08A3D39098C3",
    					"01779213E2993A77F1E1BB3B4DB77B5900B53A3A31CDE95D352C695643879824C8EE6501DC8679F5735869251256830A31357B34FF463B9292C02CD22CD30351C44F",
    // Edge case (where Go implementation returns 65 bytes of secret)
    // Nim implementation has leading `00`.
    					"001CC33294544D898781010258C2FB81F02429D2DD54D0B59B8CD2335F57498FD4E444BEC94DA7BE2BAF3E3796AFA8388F626AEB3178355991985EE5FFC9D1AACAD9"};

    static String[] ivs = {
    	"F643627AA8B91D40BA644B894C7F148E",
    	"F1D6521E4EE59248F7CCFA6D6C916A32",
    	"937D77D24441858AF5040C9A81B3D178",
    	"C7D6AE667F38A3E0C77F4AC96D82112F",
    	"735E51C37802A6E72277EE74C829A84D",
    	"617BAEA342062AE87B7A5D5D9F99371C",
    	"B535FFA95043C90C5FEEF3654E846445",
    	"3B2D2219A7EE18AB9164910821955C05",

    	"DACC23805C4ED233A7100A488AB5D68F",
    	"C5BFA3F8BF0D8436840D1AAAF091BD69",
    	"54CA4A681AEB8B5793A450100244256F",
    	"D1EB94C73D4C033EA4130B47669F4485",
    	"1F1ADF6BBDE1DFC5F922D672D2344F3A",
    	"A828F6D249F38A917CD297F7BDDE7B70",
    	"54FC8070579A17F6DAD342174062D60A",
    	"D33C7696183DA21C5CD40AB677BECE7C"
    };
	
    static String[] cipherKeys = {
    "8C2964320284FAD935AFEC1AFEC9EEF7",
    "622A9292256B012F3EBE814C0DB22095",
    "3171DCDBE794BB6CAADDDD71E1751F2C",
    "5E1519DFCABA2AF17AA4AA580CC1B76E",
    "8B7AC311FF7B7EA7B4E55E37688DA2BD",
    "6BB6E06A3A92D5C300598023330712D4",
    "D794A6B794C1E3501A24240D348B9A62",
    "45E2FFAC35B7647AD5045C8581F39BF0",

    "B2F8CDBD11B158DC68120E10A6D04C0B272DC3F698EB56B18094275076307CEB",
    "E0238BAA6B77646CD708DD00DE1FD17C6BB45F184348F512F4AE64E00CEA37B9",
    "CE009DE8D1C76C2793540A8B24774E09B0F84590B583F1A0551AC0CF1E911BF9",
    "ED5F14E36F4F2F80084571B24FD55C870B9C2AD937694B75B90E67D3591DC921",
    "1607CC9FF2B19E8F0CDA902D5996948E8EA8CFFA03F956038497684088A88B2F",
    "FC2797D1040FF162A90275EBA3FCC4330C2BDC28D23DA80B89842C2D7A6EFA06",
    "B83698789ED8E3B44E48EAAEB291B3003AD95FAF344EBA1B9071F4FB46A4E4E9",
    "5D90C579971B7B7F9ECDE55EBCE8921B807AAD45D61952228758BA80F4490E8F"
    };
    
    static String[] macKeys = {
    "2C812CB8425299B485CEE0BC97778F540380F14F",
    "8AB685E8A66256480E794B0ADC09BCF4014883C8",
    "C68EF3F3102D0CEFC0924FEF17D51FABC23EA54C",
    "F177BD066555CF25327C32C807D2E44B7DAC3EFF",
    "57176FF3103FA0F4EB58B9E49133C48B4DE9BDE6",
    "0C9ECECB80DF43CA2720DD340DD992A80AAB56DB",
    "028BCC3F5559CF43DA1B0C1A03E263C90D04DD77",
    "02DAF3FF888999C6121CA50F1D49C10FF55F1ACF",

    "6F015DDA49E0DFABD5532E6CB08709CE43F326EC",
    "68C703B3867247723D21A8C58BA9109DDBB359EF",
    "6C91DBB5FE99B94A11D0937D0F4E50F2BCB248F3",
    "D5A856ECC5820D611111BE8CEAAD781E6E4E549D",
    "9DCEB01D9657A69D40B1885C392FA850486E32B3",
    "EE66A1579D732E99A8500F48595BF25289E722DB",
    "E692EC73B0A2E68625221E1D01BA0E6B24BCB43F",
    "8613E8F86D2DD1CF3CEDC52AD91423F2F31E0003"
	};

    
	public static void main(String[] args) {

		for(int i=0;i<secrets.length;i++) {
			String cipher = "AES-128";
			if (i>3) cipher = "AES-256";
			String hasher = "SHA256";
			if (i>3) hasher = "SHA512";
			byte[] keydata = stretchKeys(fromHexString(secrets[i]), cipher, hasher);

			// Recreate the key data from reference...
			
			byte[] iv1 = fromHexString(ivs[i*2]);
			byte[] iv2 = fromHexString(ivs[i*2 + 1]);
			byte[] cipherKeys1 = fromHexString(cipherKeys[i*2]);
			byte[] cipherKeys2 = fromHexString(cipherKeys[i*2 + 1]);
			byte[] macKeys1 = fromHexString(macKeys[i*2]);
			byte[] macKeys2 = fromHexString(macKeys[i*2 + 1]);
			
			byte[] alldata = new byte[iv1.length + cipherKeys1.length + macKeys1.length
			                        + iv2.length + cipherKeys2.length + macKeys2.length];
			                        
			int offset = 0;
			System.arraycopy(iv1, 0, alldata, offset, iv1.length);
			offset+=iv1.length;
			System.arraycopy(cipherKeys1, 0, alldata, offset, cipherKeys1.length);
			offset+=cipherKeys1.length;
			System.arraycopy(macKeys1, 0, alldata, offset, macKeys1.length);
			offset+=macKeys1.length;
			
			System.arraycopy(iv2, 0, alldata, offset, iv2.length);
			offset+=iv2.length;
			System.arraycopy(cipherKeys2, 0, alldata, offset, cipherKeys2.length);
			offset+=cipherKeys2.length;
			System.arraycopy(macKeys2, 0, alldata, offset, macKeys2.length);
			offset+=macKeys2.length;
			
			System.out.println("==== Result ====");
			System.out.println(toHexString(alldata));
			System.out.println(toHexString(keydata));
		}
		
	}
	
}