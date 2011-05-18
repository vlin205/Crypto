import java.io.*;

public class Misc {

	public Misc() throws Exception {
	}

	//converts a byte array to a hex string
	public String byteToHex(byte buf[]) {
	    StringBuffer strbuf = new StringBuffer(buf.length * 2);
	    for (int i = 0; i < buf.length; i++) {
	    	if (((int) buf[i] & 0xff) < 0x10)
	    		strbuf.append("0");
	    	strbuf.append(Long.toString((int) buf[i] & 0xff, 16));
	    }
	    return strbuf.toString();
	}

	//outputs the selected string s to the file fileName
	public void outputText(String s, String fileName) {
		try {
		      PrintStream out = new PrintStream(new FileOutputStream(
		          fileName));
		      out.println(s);
		      out.close();
		      System.out.println("Outputting to '" + fileName + "'");
		      System.out.println();
		}
		catch (FileNotFoundException e) {
		      e.printStackTrace();
		}
	}

	//converts a hex string to a byte array
	public byte[] hexToByte(String s) {
	    int len = s.length();
	    byte[] data = new byte[len / 2];
	    for (int i = 0; i < len; i += 2) {
	        data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
	                             + Character.digit(s.charAt(i+1), 16));
	    }
	    return data;
	}

	//clears a byte array to be all 0s
	public void clear(byte[] data) {
		for(int i = 0; i < data.length; i++) {
			data[i] = 0;
		}
	}
}
