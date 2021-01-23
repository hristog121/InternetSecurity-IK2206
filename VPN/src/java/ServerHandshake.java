/**
 * Server side of the handshake.
 */

import java.util.Random;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.net.Socket;
import java.net.ServerSocket;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class ServerHandshake {
    /*
     * The parameters below should be learned by the server
     * through the handshake protocol.
     */

    /* Session host/port, and the corresponding ServerSocket  */
    public static ServerSocket sessionSocket;
    public String sessionHost;
    public int sessionPort;

    /* The final destination -- simulate handshake with constants */
    public String targetHost = "localhost";
    public int targetPort = 6789;

    /* Security parameters key/iv should also go here. Fill in! */
    public X509Certificate clientCert;
    public X509Certificate serverCert;
    public byte[] sessionKey;
    public byte[] sessionIV;

    /**
     * Run server handshake protocol on a handshake socket.
     * Here, we simulate the handshake by just creating a new socket
     * with a preassigned port number for the session.
     */
    public ServerHandshake() throws IOException {
        sessionPort = getPort();
        sessionSocket = new ServerSocket(sessionPort);
        sessionHost = sessionSocket.getInetAddress().getHostName();
    }

    private int getPort() {
        Random r = new Random(System.currentTimeMillis());
        return ((1 + r.nextInt(2)) * 10000 + r.nextInt(10000));
    }

    // Send ServerHello Message to client
    public void serverHello(Socket socket, String serverCertFile) throws IOException {
        HandshakeMessage sendToClient = new HandshakeMessage();
        sendToClient.putParameter("MessageType", "ServerHello");
        //ADDED HERE
        //sendToClient.send(socket);
        try {
            serverCert = VerifyCertificate.getCert(serverCertFile);
        } catch (IOException e) {
            Logger.log("Server Cert Verification Problem");
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        }
        try {
            sendToClient.putParameter("Certificate", Base64.getEncoder().encodeToString(VerifyCertificate.getCert(serverCertFile).getEncoded()));
        } catch (IOException | CertificateException e) {
            e.printStackTrace();
        }
        try {
            sendToClient.send(socket);
        } catch (IOException e) {
            Logger.log("There was a problem with sending ServerHello");
            e.printStackTrace();
        }
        Logger.log("ServerHello send to: " + socket);

    }

    // Receive client hello message

    public void receiveClientHello(Socket socket, String caCert) {
        HandshakeMessage receiveFromClient = new HandshakeMessage();
        String expectedDN = "CN=client-pf.ik2206.kth.se";
        try {
            receiveFromClient.recv(socket);
        } catch (IOException e) {
            Logger.log("There was a problem with receiving a ClientHello message");
            e.printStackTrace();
        }
        if (receiveFromClient.getParameter("MessageType").equals("ClientHello")) {
            try {
                VerifyCertificate.getVerifyCaUser(caCert, receiveFromClient.getParameter("Certificate"), expectedDN);
            } catch (Exception e) {
                e.printStackTrace();
            }

            try {
                clientCert = VerifyCertificate.decodeCert(receiveFromClient.getParameter("Certificate"));
            } catch (CertificateException e) {
                Logger.log("There was a problem with the Client Cert");
                e.printStackTrace();
            }

            Logger.log("Verify succeeded");
            Logger.log("Client cert verification successful.");
        } else {
            System.out.println("Receive ClientHello: Something went wrong - MessageType fail");
        }
    }

    public void receiveForward(Socket socket) {
        HandshakeMessage receiveFromClient = new HandshakeMessage();
        try {
            receiveFromClient.recv(socket);
        } catch (IOException e) {
            Logger.log("There was a problem with receiving a Forward message");
            e.printStackTrace();
        }
        if (receiveFromClient.getParameter("MessageType").equals("Forward")) {
            targetHost = receiveFromClient.getParameter("TargetHost");
            targetPort = Integer.valueOf(receiveFromClient.getParameter("TargetPort"));
            Logger.log("Forward set uo to: " + targetHost + ":" + targetPort);
        } else {
            System.out.println("Forward: Something went wrong - MessageType fail");
            throw new IllegalArgumentException("Forward: Something went wrong - MessageType fail");
        }
    }

    public void sendSession(Socket socket, String srvHost, int srvPort) throws NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, IOException {
        HandshakeMessage sendToClient = new HandshakeMessage();
        PublicKey clientPublicKey = clientCert.getPublicKey();
        SessionEncrypter sessionEncrypter = new SessionEncrypter(128);
        sessionKey = sessionEncrypter.getKeyBytes();
        sessionIV = sessionEncrypter.getIVBytes();

        byte[] encryptedSessionKey = HandshakeCrypto.encrypt(sessionKey, clientPublicKey);
        byte[] encryptedSessionIV = HandshakeCrypto.encrypt(sessionIV, clientPublicKey);

        sendToClient.putParameter("MessageType", "Session");
        sendToClient.putParameter("SessionKey", Base64.getEncoder().encodeToString(encryptedSessionKey));
        sendToClient.putParameter("SessionIV", Base64.getEncoder().encodeToString(encryptedSessionIV));

        sendToClient.putParameter("SessionHost", srvHost);
        sendToClient.putParameter("SessionPort", String.valueOf(srvPort));
        // Change the logging messages
        Logger.log("Session created.");
        Logger.log("Server handshake finished.");

        sendToClient.send(socket);
    }
}
