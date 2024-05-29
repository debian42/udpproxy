import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

public final class UdpClientEchoChecker implements Runnable
{
	private int sleepTime;
	private byte msg[];
	private DatagramSocket socket;
	private volatile boolean close = false;
	private byte[] localAddress;
	private InetSocketAddress serverAddress;
	private boolean verify;
	
	public void start(boolean daemon) {
		Thread t = new Thread(this);
		t.setDaemon(daemon);
		t.setName(socket.getLocalSocketAddress().toString());
		t.start();
	}
	
	public void close() {
		close = true;
	}

	private static void zeroBuffer(byte[] data) {
		for(int i=0 ; i<data.length; i++)
			data[i] = 0;
	}

	public UdpClientEchoChecker(String address, int port, int t, byte m[], boolean _verify) throws SocketException, UnknownHostException 
	{
		InetAddress localhost = InetAddress.getByName(address);
		serverAddress = new InetSocketAddress(localhost, port);
		socket = new DatagramSocket();
		socket.setReceiveBufferSize(1024 * 0xffff);
		socket.setSendBufferSize(1024 * 0xffff);
		localAddress = socket.getLocalSocketAddress().toString().getBytes(Charset.forName("ISO-8859-1"));
		socket.setSoTimeout(2000);
		sleepTime = t;
		verify = _verify;
		msg = m;
		System.out.println("REC: " + socket.getReceiveBufferSize());
		System.out.println("SND: " + socket.getSendBufferSize());
	}

	@Override
	public void run()
	{
		byte[] clientData =  new byte[0xffff];
		DatagramPacket client = null;
		try {
			client = new DatagramPacket(clientData, clientData.length, serverAddress);
		} catch (Throwable t) {
			// ign
		}
		
		long counter = 0;
		while (!close) {
			zeroBuffer(clientData);
			try 
			{
				preparePacket(counter,client);
				socket.send(client);
				if (verify) {
					socket.receive(client);
					verify(client, counter);
				}
				//System.out.println(client.getSocketAddress().toString() +  "  size:" + client.getLength() + "  cnt: " + counter);
				counter++;
				if (sleepTime >= 0)
					TimeUnit.MILLISECONDS.sleep(sleepTime);
			} catch (Throwable e) {
				//ignore
				e.printStackTrace();
			}
		}
	}

	private void preparePacket(long counter, DatagramPacket client) {
		byte[] lcb = client.getData();
		putLong(lcb, 0, counter);
		int length = 8 + localAddress.length + msg.length;
		System.arraycopy(localAddress, 0, lcb, 8, localAddress.length);
		System.arraycopy(msg, 0, lcb, 8 + localAddress.length, msg.length);
		client.setLength(length);
	}

	private void verify(DatagramPacket client, long counter) {
		int length = 8 + localAddress.length + msg.length;
		if (client.getLength() != length)
			System.err.println("PACKET-MISMATCH");
		byte ar[] = new byte[length];
		putLong(ar, 0, counter);
		System.arraycopy(localAddress, 0, ar, 8, localAddress.length);
		System.arraycopy(msg, 0, ar, 8 + localAddress.length, msg.length);
		byte clbuf[] = new byte[client.getLength()];
		System.arraycopy(client.getData(), 0, clbuf, 0, client.getLength());
		if (!Arrays.equals(ar, clbuf))
			System.err.println("PACKET-MISMATCH");
	}

	private static void putLong(byte[] ar, int o, long v)
	{
		ar[o+0] = (byte) (v & 0xFF);
		ar[o+1] = (byte) ((v >> 8) & 0xFF);
		ar[o+2] = (byte) ((v >> 16) & 0xFF);
		ar[o+3] = (byte) ((v >> 24) & 0xFF);
		ar[o+4] = (byte) ((v >> 32) & 0xFF);
		ar[o+5] = (byte) ((v >> 40) & 0xFF);
		ar[o+6] = (byte) ((v >> 48) & 0xFF);
		ar[o+7] = (byte) ((v >> 56) & 0xFF);
	}

	public static void main(String... args) throws Throwable
	{
		if (args.length < 4 || args.length > 5) {
			System.err.println("Wrong number of Arguments!\n" + "UdpClientEchoChecker destIP port sleepTimeMs 'Text to verify' [-v]\n-v disable verify");
			System.exit(1);
		}

		int port = Integer.parseInt(args[1]);
		int sleepTime = Integer.parseInt(args[2]);
		byte msg[] = args[3].getBytes(Charset.forName("ISO-8859-1"));
		boolean verify = true;
		if (args.length == 5) {
			verify = ! "-v".equalsIgnoreCase(args[4]);
		}
		System.out.println("sleepTime: " + sleepTime);
		System.out.println("msg: " + msg);
		UdpClientEchoChecker server = new UdpClientEchoChecker(args[0], port, sleepTime, msg, verify);
		server.start(false);
	}

}

