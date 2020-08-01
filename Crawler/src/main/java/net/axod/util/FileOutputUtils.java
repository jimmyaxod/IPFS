package net.axod.util;

import java.io.*;
import java.util.*;
import java.util.zip.*;

public class FileOutputUtils {
	public long FILE_ROLL = 3600;						// Default to hourly
	public String FILE_DIR = null;
	public boolean DO_FLUSHES = false;
	public boolean DEDUP = true;
	public boolean GZIP = false;
	private HashMap bufferedWriters = new HashMap();	// name -> BufferedWriter
	private HashMap outputfiles = new HashMap();		// name -> Time value
	private HashMap dedupBuffers = new HashMap();		// name -> LinkedHashSet(line)

	public int DEDUP_SIZE = 100;						// dedup on last 100 lines

	public static long total_lines_written = 0;
	public static long total_lines_ignored = 0;

	public String toString() {
		return "FileOutputUtils written=" + total_lines_written + " ignored=" + total_lines_ignored;
	}

	public String getCurrentTimestamp() {
		long now = System.currentTimeMillis()/1000;
		now = (long)(FILE_ROLL * Math.floor(now / FILE_ROLL));
		return Long.toString(now);
	}

	/**
	 * Write some data out
	 *
	 */
	public void writeFile(String f, String data) {
		if (FILE_DIR==null) return;
		synchronized(bufferedWriters) {
			if (DEDUP) {
				LinkedHashSet lhs = (LinkedHashSet)dedupBuffers.get(f);
				if (lhs==null) {
					lhs = new LinkedHashSet();
					dedupBuffers.put(f, lhs);
				}
				if (lhs.contains(data)) {
					total_lines_ignored++;
					return;
				}
				lhs.add(data);
				// Now trim it down to size if it's needed...
				Iterator i = lhs.iterator();
				while(i.hasNext() && lhs.size()>DEDUP_SIZE) {
					i.next();
					i.remove();
				}
			}
		
			try {
				long now = System.currentTimeMillis()/1000;
				now = (long)(FILE_ROLL * Math.floor(now / FILE_ROLL));
				BufferedWriter bw = (BufferedWriter) bufferedWriters.get(f);
				Long ct = (Long) outputfiles.get(f);

				if (ct==null || bw==null || (ct.longValue()!=now)) {
					if (bw!=null) close();

					if (GZIP) {
						FileOutputStream fos = new FileOutputStream(FILE_DIR + f + "_" + now + ".gz");
						bw = new BufferedWriter(new OutputStreamWriter(new GZIPOutputStream(fos)), 1024*1024);
					} else {
						bw = new BufferedWriter(new FileWriter(FILE_DIR + f + "_" + now), 1024*1024);
					}
					bufferedWriters.put(f, bw);
					outputfiles.put(f, new Long(now));
				}
				bw.write(data);
				total_lines_written++;
				if (DO_FLUSHES) bw.flush();
			} catch(IOException ioe) {
				System.out.println("FileOutputUtils Exception writing " + f);
				ioe.printStackTrace();
			}
		}
	}

	/**
	 * Close all output files...
	 *
	 */
	public void close() {
		synchronized(bufferedWriters) {
			Iterator i = bufferedWriters.keySet().iterator();
			while(i.hasNext()) {
				String n = (String)i.next();
				BufferedWriter bw = (BufferedWriter)bufferedWriters.get(n);
				Long ct = (Long) outputfiles.get(n);
				System.out.println("Closing " + n + " " + ct);
				try {
					bw.close();
				} catch(IOException ioe) {
					System.out.println("FileOutputUtils Exception closing");
				}
			}
		
			bufferedWriters = new HashMap();
			outputfiles = new HashMap();
			dedupBuffers = new HashMap();
		}
	}	
}
