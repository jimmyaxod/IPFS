package net.axod.protocols.yamux;

import net.axod.io.*;

import java.util.*;
import java.util.logging.*;
import java.nio.*;

/**
 * This knows about Yamux
 *
 */

public class YamuxSession {
    private static Logger logger = Logger.getLogger("net.axod.protocols");
	private HashMap activeIOPlugins = new HashMap();

	private HashSet notSentSYN = new HashSet();
	private HashSet notSentACK = new HashSet();
	
	private int outgoingStreamID = 3;			// NB Must be odd.

	private IOPluginFactory iopf = null;
	
	private static final byte YAMUX_TYPE_DATA = 0;
	private static final byte YAMUX_TYPE_WINDOW_UPDATE = 1;
	private static final byte YAMUX_TYPE_PING = 2;
	private static final byte YAMUX_TYPE_GO_AWAY = 3;

	private static final short YAMUX_FLAG_SYN = 1;
	private static final short YAMUX_FLAG_ACK = 2;
	private static final short YAMUX_FLAG_FIN = 4;
	private static final short YAMUX_FLAG_RST = 8;

	public YamuxSession(IOPluginFactory incoming_iopf) {
		iopf = incoming_iopf;
	}

	public void setupOutgoingStream(IOPlugin iop) {
		setupOutgoingStream(outgoingStreamID, iop);
		outgoingStreamID+=2;
	}
	
	public void setupOutgoingStream(int id, IOPlugin iop) {
		// For an outgoing stream, we should send a SYN on the first packet...
		logger.fine("Yamux setting up new stream " + id);
		if (activeIOPlugins.containsKey(id)) {
			System.err.println("Yamux already have stream setup for " + id);
			return;
		}
		activeIOPlugins.put(id, iop);	// Store it here...
		notSentSYN.add(id);
	}

	/**
	 * Process data
	 *
	 * @param	in	Input buffer
	 * @param	out	Output buffer
	 */
	public void process(ByteBuffer in, ByteBuffer out) {
		in.flip();
		while(in.remaining()>0) {
			try {
				byte m_ver = in.get();
				byte m_type = in.get();
				short m_flags = in.getShort();
				int m_stream = in.getInt();
				int m_length = in.getInt();
				
				//System.out.println("Yamux packet ver=" + m_ver + " type=" + m_type + " flags=" + m_flags + " stream=" + m_stream + " len=" + m_length);
				
				if (m_type==YAMUX_TYPE_WINDOW_UPDATE || m_type==YAMUX_TYPE_DATA) {
					if ((m_flags & YAMUX_FLAG_SYN) == YAMUX_FLAG_SYN) {
						// New stream...
						IOPlugin iop = iopf.getIOPlugin(null, null);			// For now we won't bother with the Node or ISA.
						
						if (activeIOPlugins.containsKey(m_stream)) {
							System.err.println("Yamux already have stream setup for " + m_stream);
						} else {
							activeIOPlugins.put(m_stream, iop);	// Store it here...
							notSentACK.add(m_stream);
						}                      
//						System.err.println("Yamux incoming stream " + m_stream);
						// TODO...
					}
				}
				
				if ((m_flags & YAMUX_FLAG_RST) == YAMUX_FLAG_RST) {
					// TODO: Close stream	
				}

				if ((m_flags & YAMUX_FLAG_FIN) == YAMUX_FLAG_FIN) {
					// TODO: Close stream	
				}
				
				if (m_type==YAMUX_TYPE_DATA) {
					byte[] d = new byte[m_length];
					in.get(d);

					IOPlugin iop = (IOPlugin)activeIOPlugins.get(m_stream);
					if (iop==null) {
						// ERROR!
//						System.err.println("Yamux no stream with id " + m_stream);
					} else {
						iop.in.put(d);
						logger.fine("Yamux got data " + iop.in.position() + " for stream " + m_stream);
						iop.work();
					}					
				} else if (m_type==YAMUX_TYPE_WINDOW_UPDATE) {
					
				} else if (m_type==YAMUX_TYPE_PING) {
					// Send a ping back...
					byte[] dummy = new byte[0];
					writeYamux(out, dummy, YAMUX_TYPE_PING, m_stream, YAMUX_FLAG_ACK);
				} else if (m_type==YAMUX_TYPE_GO_AWAY) {
					// TODO: Handle this
				}
			} catch(BufferUnderflowException bue) {
				in.rewind();		// Try again later...
				break;
			}
			in.compact();
			in.flip();
		}
		in.compact();
		
		Iterator i = activeIOPlugins.keySet().iterator();
		while(i.hasNext()) {
			Integer stream_id = (Integer)i.next();
			IOPlugin iop = (IOPlugin)activeIOPlugins.get(stream_id);

			if (iop.wantsToWork()) {
				iop.work();
			}

			// Check the out buffer...
			if (iop.out.position()>0) {
				if ((stream_id & 1)==0) {
					// It was an incoming stream...
					logger.info("Yamux our plugin " + stream_id + " wants to write data " + iop.out.position());
					
				} else {
					// It was an outgoing stream...	
				}
//				logger.info("Yamux our plugin " + stream_id + " wants to write data " + iop.out.position());
				iop.out.flip();
				byte[] data = new byte[iop.out.remaining()];
				iop.out.get(data);
				iop.out.compact();
				short flags = 0;
				if (notSentSYN.contains(stream_id)) {
					flags = YAMUX_FLAG_SYN;
					notSentSYN.remove(stream_id);
				}

				if (notSentACK.contains(stream_id)) {
					flags = YAMUX_FLAG_ACK;
					notSentACK.remove(stream_id);
				}
				
				writeYamux(out, data, stream_id, flags);
			}
		}
	}

	/**
	 * Write
	 *
	 */
	public static void writeYamux(ByteBuffer dest, byte[] multi_data, int m_stream, short m_flags) {
		writeYamux(dest, multi_data, 0, m_stream, m_flags);
	}

	/**
	 * Write a yamux packet out
	 *
	 */
	public static void writeYamux(ByteBuffer dest, byte[] multi_data, int m_type, int m_stream, short m_flags) {
		dest.put((byte)0);			// ver
		dest.put((byte)m_type);		// type
		dest.putShort(m_flags);
		dest.putInt(m_stream);		// Stream ID
		dest.putInt(multi_data.length);
		dest.put(multi_data);
	}

}