package net.axod.ipfscrawl;

import net.axod.io.*;
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
					byte[] a = new byte[in.remaining()];
					in.compact();
					System.out.println("NOISE DATA " + ByteUtil.toHexString(a));
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