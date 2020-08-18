package net.axod.ipfscrawl;

import net.axod.io.*;
import net.axod.pb.*;
import net.axod.util.*;
import net.axod.ipfscrawl.*;
import net.axod.protocols.multistream.*;
import net.axod.protocols.yamux.*;
import net.axod.handlers.*;
import net.axod.crypto.keys.*;
import net.axod.crypto.secio.*;

import java.nio.*;
import java.net.*;
import java.util.*;
import java.util.logging.*;
import java.security.*;

public class IPFSIOPluginIn extends IOPlugin {
    private static Logger logger = Logger.getLogger("net.axod.ipfscrawl");
	IncomingMultistreamSelectSession multi_secio = new IncomingMultistreamSelectSession();
	IncomingMultistreamSelectSession multi_yamux = new IncomingMultistreamSelectSession();

	ClientDetails client = new ClientDetails();
	
	YamuxSession yamux = new YamuxSession(new HandlerIncomingFactory(client), false);	// For now...		
	ByteBuffer yamuxInbuffer = ByteBuffer.allocate(200000);
	
	// My RSA keys
	static KeyPair mykeys = null;	

	static {
		mykeys = KeyManager.getKeys();
	}

	SecioSession secio;
	boolean sent_secio_starter = false;

	public IPFSIOPluginIn(Node n, InetSocketAddress isa) {
		System.out.println("INCOMING CONNECTION " + n + " on " + isa);
		
		client.node = n;
		client.host = n.getInetSocketAddress().getAddress().getHostAddress();
	}

	public boolean wantsToWork() {
		if (secio!=null & !sent_secio_starter) return true;
		return false;
	}

	public void work() {
		long now = System.currentTimeMillis();
		if (!multi_secio.hasHandshaked()) {
			String proto = multi_secio.process(in, out);
			if (proto!=null) {				
				// For now, log it...
				Crawl.outputs.writeFile("in_connect_protocols", now + "," + proto.trim() + "\n");
				if (proto.equals(OutgoingMultistreamSelectSession.PROTO_SECIO)) {
					multi_secio.sendAccept(out);
					System.out.println("Sent accept for secio...");
					secio = new SecioSession(true);
					client.secio = secio;
				} else if (proto.equals(OutgoingMultistreamSelectSession.PROTO_NOISE)) {
					multi_secio.sendAccept(out);
					System.out.println("Sent accept for noise...");
					
					// OK...
				} else {
					
					close();
					return;
				}
			}
		} else {
			if (multi_secio.getProtocol().equals(OutgoingMultistreamSelectSession.PROTO_NOISE)) {
				if (in.position()>0) {
					in.flip();
					
					in.order(ByteOrder.BIG_ENDIAN);
					int packet_size = in.getShort();
					System.out.println("NOISE handshake " + packet_size);

					byte[] a = new byte[packet_size];
					in.get(a);
					in.compact();
					System.out.println("NOISE DATA " + ByteUtil.toHexString(a));

					// 32 byte 'ne'
					// The rest 'ciphertext'
					//
					
					try {
						NoisePayload.NoiseHandshakePayload nhp = NoisePayload.NoiseHandshakePayload.parseFrom(a);
					
						System.out.println("NOISE NHP " + nhp);
					} catch(Exception e) {
						System.err.println("Noise Exception " + e);	
					}

// XX handshake goes:
// {E}
// {E, DHEE, S, DHES}
// {S, DHSE}

// Example stage 2
// DH Key...
// 05 bf 04 c3 5b ca d6 93 5b c4 f1 6e ff 97 67 ff
// 2d a8 1f 2f e8 e6 52 e7 18 27 e4 30 30 e5 78 35
//
// 48 byte signature?
// c4 21 81 5c d0 95 bb fb 19 a7 4c ed 10 6c c9 80
// fe 7e 7d 4d 50 7b aa fa 0c 62 29 7d 8c cd ac 14
// 03 49 41 a5 27 0e c2 98 70 7e f4 73 97 d6 af c4
//
// extra payload stuff
// be b9 63 0c f2 15 00 53 5a 6f a1 e8 64 51 90 65
// 26 cf 91 03 d9 de c7 31 fc e5 04 40 85 7c 2e 1b
// f2 9b 5c 9d a6 3e 9b 4b 67 45 0b a7 e7 88 4a 59
// ab 97 37 b8 9b 22 59 fc 2a 1e 0d 2a 1d f9 d2 b1
// 4a 1e ae 3c 17 c9 1f 25 b6 92 2e d4 85 e3 34 f2
// 9b de 55 20 de b0 bb bd d9 55 98 fa 3f 9d 22 01
// 09ec945b80e152facf2525d1da71dc834692139d8431a07e6372a74e3b83cde9b3b31a9a22ab4b5cfa85614dc0d1e2e1b00ce2ce26a330136f8b74f93a1fe6e5142144820caea60f9d77c0b904334e6aae002d23860382fdaba0cf6e235e3b9a8437c224336ce4c7ffaffac393f9563c71463dab972afd22109d3edbb7b620ee264b69c747c7e8f8682d2c153d5756c614b1eab1723c8ddbab19e8979608da2402db43b004469331b19ff8911f7f872305a104c3e9f99c929842bc9377ecddeb8901fc62d80d025d818d26019139d9e79032886a3d62ea68862975c9fa449e2d9a4a8b478e51f3fe716b0d495053e064ad57d5ed994766d977957e058b5a97468f96be101d6474a8904354fb4403f12b2a03a9cbcd5ee70d88e04e79bbd7d04e04ff737ff42167c79ca1ab8b26631ccf79adf79db441b9086d5a118c1c39e03da81d4da39cf4f5c210adc12c2ac91694f05f891a3c935a51ee27ae4561484312ef84976768adab6a874d354c465f5fd8e5ed9e6fb1bcc0762f88c73514082d1b84be45bb1db45e61cdcd85ecc01600e9cd34f45fe603937f3e78ef2eef373b303db2ed1bfbe12949d06275e1d1e5b03a4496fe7e9327f739cf399b382aaf0d9f6957d6344f531dddf8f22fb9b38b5ed84b441bac88df8c1e938d321164003e39cc


// eg
// 0020
// c7 71 48 7f d6 c1 21 15
// 7f 69 00 fa 94 08 d9 f9
// 68 ac 7f b6 79 6a 6f 0f
// 72 35 20 95 19 ce a4 76


				}
			
			} else if (multi_secio.getProtocol().equals(OutgoingMultistreamSelectSession.PROTO_SECIO)) {
				try {
					// Do the secio stuff..
					LinkedList spackets = secio.process(in, out, mykeys);
					if (secio.handshaked()) {
						for(int i=0;i<spackets.size();i++) {
							byte[] pack = (byte[])spackets.get(i);
							processSecioPacket(pack);
						}
		
						// If we need to do something inside...
						processSecioPacket(null);
					}
				} catch(SecioException se) {
					logger.info("Exception within secio " + se);
					close();
					return;
				} catch(BufferUnderflowException bue) {
					logger.info("Exception processing packet underflow " + bue);
					bue.printStackTrace();					
				} catch(Exception e) {
					logger.info("Exception processing packet " + e);
					e.printStackTrace();
					close();
					return;					
				}
			}
			sent_secio_starter = true;
		}		
	}

	private void processSecioPacket(byte[] plainText) throws Exception {
		if (plainText!=null) yamuxInbuffer.put(plainText);	// Add it on...

		ByteBuffer outbuff = ByteBuffer.allocate(8192);		// For now...
		
		// multistream select yamux
		if (!multi_yamux.hasHandshaked()) {
			String proto = multi_yamux.process(yamuxInbuffer, outbuff);
			if (proto!=null) {
				if (proto.equals(OutgoingMultistreamSelectSession.PROTO_YAMUX)) {
					multi_yamux.sendAccept(outbuff);
				} else {
					System.err.println("*** *** EXPECTING YAMUX " + proto);
					close();
				}
			}
		} else {
			processYamuxPackets(yamuxInbuffer);

			// We have some in data...
		}
		
		// Send any multistream handshake stuff to next layer
		outbuff.flip();
		if (outbuff.remaining()>0) {
			logger.fine("Sending data " + outbuff.remaining());
			byte[] wdata = new byte[outbuff.remaining()];
			outbuff.get(wdata);
			secio.write(out, wdata);
		}
		
	}

	/**
	 * Deal with Yamux packets...
	 *
	 */
	public void processYamuxPackets(ByteBuffer inbuff) throws Exception {
		ByteBuffer yo = ByteBuffer.allocate(8192);	// For ping replies etc...
		yamux.process(inbuff, yo);

		// Now we need to send anything that yamux wanted to send...
		if (yo.position()>0) {
			logger.fine("Yamux sending data... " + yo.position());
			secio.write(out, yo);		// Write it out...
		}
	}
	
	public void closing() {
	}
}