package net.axod.util;

import java.util.concurrent.atomic.*;
import java.util.*;

/**
 * Util to do some basic timing tasks for us.
 *
 */
public class Timing {
	private static HashMap counts = new HashMap();
	private static HashMap times = new HashMap();
	private static HashMap enters = new HashMap();

	/**
	 * Dump timing stats to stderr
	 *
	 */
	public static void showTimings() {
		System.err.println("*Timing* count time id");
		synchronized(times) {
			Iterator i = times.keySet().iterator();
			while(i.hasNext()) {
				String id = (String)i.next();
				AtomicLong c = (AtomicLong)counts.get(id);
				AtomicLong t = (AtomicLong)times.get(id);
				// Show the data...
				System.err.println("*Timing* " + c.get() + "\t" + t.get() + "\t" + id);
			}
		}
		System.err.println("*Timing*");
	}
	
	/**
	 * Enter a timing area
	 *
	 */
	public static void enter(String id) {
		synchronized(times) {
			long ctime = System.currentTimeMillis();
			enters.put(id, new Long(ctime));
		}
	}
	
	/**
	 * Leave a timing area
	 *
	 */
	public static void leave(String id) {
		synchronized(times) {
			long etime = System.currentTimeMillis();
			Long l = (Long)enters.get(id);
			if (l==null) {
				System.err.println("leave without enter? " + id);
				return;
			}
			enters.remove(id);
			long ctime = l.longValue();
		
			AtomicLong c = (AtomicLong)counts.get(id);
			if (c==null) {
				c = new AtomicLong(0);
				counts.put(id, c);
			}
			c.incrementAndGet();
		
			AtomicLong t = (AtomicLong)times.get(id);
			if (t==null) {
				t = new AtomicLong(0);
				times.put(id, t);
			}
			t.addAndGet(etime - ctime);
		}
	}
}