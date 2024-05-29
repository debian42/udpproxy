import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.net.UnknownHostException;

public final class UdpEchoServer implements Runnable
{
	private DatagramSocket socket;
	private volatile boolean close = false;
	private boolean sendResponse;
	
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

	public UdpEchoServer(String address, int port, boolean _sendResponse) throws SocketException, UnknownHostException 
	{
		InetAddress localhost = InetAddress.getByName(address);
		InetSocketAddress serverAddress = new InetSocketAddress(localhost, port);
		socket = new DatagramSocket(serverAddress);
		socket.setReceiveBufferSize(1024*1024);
		socket.setSendBufferSize(1024*1024);
		sendResponse = _sendResponse;
		System.out.println("REC: " + socket.getReceiveBufferSize());
		System.out.println("SND: " + socket.getSendBufferSize());	
	}

	@Override
	public void run()
	{
		byte[] clientData =  new byte[0xffff];
		DatagramPacket client = new DatagramPacket(clientData, clientData.length);
		long counter = 0;
		while (!close) {
			zeroBuffer(clientData);
			try {
				socket.receive(client);
				if (sendResponse)
					socket.send(client);
				counter++;
				//System.out.println(client.getSocketAddress() + "  cnt: " + counter);
			} catch (IOException e) {
				//ignore
				e.printStackTrace();
			}
		}
	}

	public static void main(String... args) throws Throwable
	{
		if (args.length < 2 || args.length > 3) {
			System.err.println("Wrong number of Arguments!\n" + "UdpEchoServer listenIP port [-d]\n -d disable response");
			System.exit(1);
		}
		boolean sendResponse = true;
		if (args.length == 3) {
			sendResponse = ! "-d".equalsIgnoreCase(args[2]);
		}
		int port = Integer.parseInt(args[1]);
		UdpEchoServer server = new UdpEchoServer(args[0], port, sendResponse);
		server.start(false);
	}

}

