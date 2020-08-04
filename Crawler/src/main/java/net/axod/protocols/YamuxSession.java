package net.axod.protocols;

import java.util.*;
import java.util.logging.*;
import java.nio.*;

/**
 * This knows about Yamux
 *
 */

public class YamuxSession {
    private static Logger logger = Logger.getLogger("net.axod.protocols");
	private HashMap activeInbuffers = new HashMap();

	private static final byte YAMUX_TYPE_DATA = 0;
	private static final byte YAMUX_TYPE_WINDOW_UPDATE = 1;
	private static final byte YAMUX_TYPE_PING = 2;
	private static final byte YAMUX_TYPE_GO_AWAY = 3;

	private static final short YAMUX_FLAG_SYN = 1;
	private static final short YAMUX_FLAG_ACK = 2;
	private static final short YAMUX_FLAG_FIN = 4;
	private static final short YAMUX_FLAG_RST = 8;

	private static final int BUFFER_SIZE_IN = 100000;
	
	public YamuxSession() {
	}
	
	public void setupStream(int id) {
		logger.fine("Yamux setting up new stream " + id);
		if (activeInbuffers.containsKey(id)) {
			// ERROR!	
		}
		ByteBuffer in = ByteBuffer.allocate(BUFFER_SIZE_IN);
		activeInbuffers.put(id, in);		
	}

	/**
	 * Get an input buffer so we can read from it...
	 *
	 */
	public ByteBuffer getInputBuffer(int m_stream) {
		return (ByteBuffer)activeInbuffers.get(m_stream);	
	}
	
	/**
	 * Process data
	 *
	 * @param	in	Input buffer
	 * @param	out	Output buffer we can write to
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
				if (m_type==YAMUX_TYPE_WINDOW_UPDATE || m_type==YAMUX_TYPE_DATA) {
					if ((m_flags & YAMUX_FLAG_SYN) == YAMUX_FLAG_SYN) {
						// New stream...
						setupStream(m_stream);
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

					ByteBuffer bb = (ByteBuffer)activeInbuffers.get(m_stream);
					if (bb==null) {
						// ERROR!	
					} else {
						// TODO: Handle overflowing data
						bb.put(d);
						logger.fine("Yamux got data " + bb.position() + " for stream " + m_stream);
					}
					
				} else if (m_type==YAMUX_TYPE_WINDOW_UPDATE) {
					
				} else if (m_type==YAMUX_TYPE_PING) {
					// Send a ping back...
					byte[] dummy = new byte[0];
					writeYamux(out, dummy, YAMUX_TYPE_PING, m_stream, (short)2);					
				} else if (m_type==YAMUX_TYPE_GO_AWAY) {

				}
			} catch(BufferUnderflowException bue) {
				in.rewind();		// Try again later...
				break;
			}
			in.compact();
			in.flip();
		}
		in.compact();
		
		// See if we should write anything out
	}

	public static void writeYamux(ByteBuffer dest, byte[] multi_data, int m_stream, short m_flags) {
		dest.put((byte)0);		// ver
		dest.put((byte)0);		// type
		dest.putShort(m_flags);
		dest.putInt(m_stream);	// Stream ID
		dest.putInt(multi_data.length);
		dest.put(multi_data);
	}

	public static void writeYamux(ByteBuffer dest, byte[] multi_data, int m_type, int m_stream, short m_flags) {
		dest.put((byte)0);			// ver
		dest.put((byte)m_type);		// type
		dest.putShort(m_flags);
		dest.putInt(m_stream);		// Stream ID
		dest.putInt(multi_data.length);
		dest.put(multi_data);
	}

}