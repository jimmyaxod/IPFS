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
import java.util.*;
import java.nio.*;

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
    public boolean sent_noise_opening = false;
    public boolean recv_first_packet = false;

    private byte[] incoming_ne;
    private byte[] incoming_ns;
    private byte[] incoming_ciphertext;
    
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

	/**
	 * Get the 32 byte encoded public key
	 *
	 */
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
	
	/**
	 * Process handshake, then data.
	 *
	 * @return	List of decrypted packets.
	 */
	public LinkedList process(ByteBuffer in, ByteBuffer out, KeyPair keys) throws NoiseException {
		LinkedList inq = new LinkedList();
		
		// First we need to send our opening public key (32 bytes).
		if (!sent_noise_opening) {
			byte[] data = getEncodedPublicKey();
			out.order(ByteOrder.BIG_ENDIAN);
			out.putShort((short)data.length);
			out.put(data);
			sent_noise_opening = true;	
			System.out.println("Sent noise key - " + ByteUtil.toHexString(data));
		}

		// Now we have to do the noise protocol stuff...
		if (in.position()>0) {
			in.flip();

			in.order(ByteOrder.BIG_ENDIAN);
			int packet_size = in.getShort();
			byte[] a = new byte[packet_size];
			in.get(a);
			in.compact();

			if (!recv_first_packet) {
				if (a.length<80) throw (new NoiseException("Packet is less than 80 bytes"));
				incoming_ne = new byte[32];
				incoming_ns = new byte[48];
				incoming_ciphertext = new byte[a.length - 80];
				
				System.arraycopy(a, 0, incoming_ne, 0, 32);
				System.arraycopy(a, 32, incoming_ns, 0, 48);
				if (incoming_ciphertext.length>0) System.arraycopy(a, 80, incoming_ciphertext, 0, a.length - 80);
				
				System.out.println("Noise: ne = " + ByteUtil.toHexString(incoming_ne));
				System.out.println("Noise: ns = " + ByteUtil.toHexString(incoming_ns));
				System.out.println("Noise: cophertext = " + ByteUtil.toHexString(incoming_ciphertext));

				// Now we need to validate ne, and convert it to a PublicKey
				// Next we need to verify, and reply with our bits...
				
				recv_first_packet = true;
			} else {
				System.out.println("NOISE DATA " + ByteUtil.toHexString(a));
			}
			
		}		
		return inq;
	}

	/**
	 * Simple tester...
	 *
	 */
	public static void main(String[] args) throws Exception {
		NoiseSession ns = new NoiseSession();
		byte[] k = ns.getEncodedPublicKey();
			
		System.out.println("key=" + ByteUtil.toHexString(k));
	}	
	
}