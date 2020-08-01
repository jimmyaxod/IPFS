package net.axod.crypto;

import org.bouncycastle.*;
import org.bouncycastle.asn1.x9.*;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.crypto.*;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.generators.*;
import org.bouncycastle.math.ec.*;

import java.security.spec.ECPoint;
import java.security.SecureRandom;
import java.math.*;

public class ECHelper {

	/**
	 * Create the shared secret, by calculating xy * i
	 *
	 */
    public static byte[] createSharedSecret(byte[] xy, byte[] i) {
    	// First we need to move to BouncyCastle...

		// Get domain parameters for example curve secp256r1
		org.bouncycastle.asn1.x9.X9ECParameters ecp = org.bouncycastle.asn1.sec.SECNamedCurves.getByName("secp256r1");
		org.bouncycastle.math.ec.ECCurve curve = ecp.getCurve();
		org.bouncycastle.math.ec.ECPoint p = curve.decodePoint(xy);
		org.bouncycastle.math.ec.ECPoint q = p.multiply(new BigInteger(i));		
		return q.getEncoded(false);
    }
	
	
  public static String toHex(byte[] data) {
    StringBuilder sb = new StringBuilder();
    for (byte b: data) {
      sb.append(String.format("%02x", b&0xff));
    }
    return sb.toString();
  }
/*
  public static void main(String[] argv) {
    // Get domain parameters for example curve secp256r1
    X9ECParameters ecp = SECNamedCurves.getByName("secp256r1");
    ECDomainParameters domainParams = new ECDomainParameters(ecp.getCurve(),
                                                             ecp.getG(), ecp.getN(), ecp.getH(),
                                                             ecp.getSeed());

    // Generate a private key and a public key
    AsymmetricCipherKeyPair keyPair;
    ECKeyGenerationParameters keyGenParams = new ECKeyGenerationParameters(domainParams, new SecureRandom());
    ECKeyPairGenerator generator = new ECKeyPairGenerator();
    generator.init(keyGenParams);
    keyPair = generator.generateKeyPair();

    ECPrivateKeyParameters privateKey = (ECPrivateKeyParameters) keyPair.getPrivate();
    ECPublicKeyParameters publicKey = (ECPublicKeyParameters) keyPair.getPublic();
    byte[] privateKeyBytes = privateKey.getD().toByteArray();

    // First print our generated private key and public key
    System.out.println("Private key: " + toHex(privateKeyBytes));
    System.out.println("Public key: " + toHex(publicKey.getQ().getEncoded(true)));

    // Then calculate the public key only using domainParams.getG() and private key
    ECPoint Q = domainParams.getG().multiply(new BigInteger(privateKeyBytes));
    System.out.println("Calculated public key: " + toHex(Q.getEncoded(true)));

    // The calculated public key and generated public key should always match
    if (!toHex(publicKey.getQ().getEncoded(true)).equals(toHex(Q.getEncoded(true)))) {
      System.out.println("ERROR: Public keys do not match!");
    } else {
      System.out.println("Congratulations, public keys match!");
    }
    
    // Try scalar multiply...
    
    byte[] bi = {1,5,49};
    
    ECPoint m1 = publicKey.getQ();
    ECPoint mm = m1.multiply(new BigInteger(bi));
    System.out.println("Multiply " + toHex(m1.getEncoded(true)));
    System.out.println("Multiply " + toHex(mm.getEncoded(true)));
    
  }
*/
  
}	
	
	
