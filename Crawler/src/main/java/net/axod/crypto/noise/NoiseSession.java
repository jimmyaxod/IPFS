package net.axod.crypto.noise;

import net.axod.util.*;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;

import java.security.interfaces.*;
import java.security.spec.*;
import java.security.*;
import java.math.*;

/**
 * A Noise Session can be used to talk noise.
 *
 * DH25519
 * ChaChaPoly
 * HashSHA256
 *
 */
public class NoiseSession {
    private static final String ENCRYPT_ALGO = "ChaCha20";
	
    public KeyPair dhKeys;

	public NoiseSession() {
		try {
			X9ECParameters curveParams = CustomNamedCurves.getByName("Curve25519");
			ECParameterSpec ecSpec = new ECParameterSpec(curveParams.getCurve(), curveParams.getG(), curveParams.getN(), curveParams.getH(), curveParams.getSeed());
	
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
			kpg.initialize(ecSpec);

			dhKeys = kpg.generateKeyPair();
		} catch(Exception e) {
			System.err.println("Exception generating DH25519 keypair");	
		}
	}

	public byte[] getEncodedPublicKey() {
		PublicKey publicKey = dhKeys.getPublic();
		ECPublicKey ecpk = (ECPublicKey)publicKey;			
		BigInteger x = ecpk.getW().getAffineX();
			
		byte[] xa = x.toByteArray();
		byte[] r = new byte[32];
		
		// Copy it, right aligned.
		System.arraycopy(xa, 0, r, (xa.length - r.length), xa.length);
		return r;		
	}
	
	public static void main(String[] args) throws Exception {
		NoiseSession ns = new NoiseSession();
		byte[] k = ns.getEncodedPublicKey();
			
		System.out.println("key=" + ByteUtil.toHexString(k));
	}	
	
}