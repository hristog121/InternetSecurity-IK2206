/**
 * Client side of the handshake.
 */

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.net.Socket;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

public class ClientHandshake {
    /*
     * The parameters below should be learned by the client
     * through the handshake protocol.
     */

    /* Session host/port  */
    public static String sessionHost = "localhost";
    public static int sessionPort = 12345;
    public X509Certificate clientCert;
    public X509Certificate serverCert;

    /* Security parameters key/iv should also go here. Fill in! */
    public byte[] sessionKey;
    public byte[] sessionIV;

    /**
     * Run client handshake protocol on a handshake socket.
     * Here, we do nothing, for now.
     */
    public ClientHandshake(Socket handshakeSocket) throws IOException, CertificateException {

    }

    // Send Client Hello message to the server for the handshake
    public void clientHello(Socket socket, String clientCertFile) throws IOException, CertificateException {
        HandshakeMessage sendToServer = new HandshakeMessage();
        clientCert = VerifyCertificate.getCert(clientCertFile);
        sendToServer.putParameter("MessageType", "ClientHello");
        sendToServer.putParameter("Certificate", VerifyCertificate.encodeCertificate(clientCert));
        sendToServer.send(socket);
        Logger.log("ClientHello msg sent to " + socket);

    }

    // Receive server hello + cert from the server
    public void receiveServerHello(Socket socket, String caCert) throws Exception {
        HandshakeMessage receiveFromServer = new HandshakeMessage();
        receiveFromServer.recv(socket);
        if (receiveFromServer.getParameter("MessageType").equals("ServerHello")) {
           VerifyCertificate.getVerifyCaUser(caCert,receiveFromServer.getParameter("Certificate"));
           serverCert = VerifyCertificate.decodeCert(receiveFromServer.getParameter("Certificate"));
           Logger.log("Verify succeeded");
        } else {
            System.out.println("Receiving ServerHello: Something went wrong - MessageType fail");
        }
    }

    public void sendForward(Socket socket, String targetHost, String targetPort) throws IOException {
        HandshakeMessage sendToServer = new HandshakeMessage();
        sendToServer.putParameter("MessageType", "Forward");
        sendToServer.putParameter("TargetHost", targetHost);
        sendToServer.putParameter("TargetPort", targetPort);
        sendToServer.send(socket);
        Logger.log("Forward Message sent to " + socket);

    }

    public void receiveSession(Socket socket, String privKeyFile) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException {
        try {
        HandshakeMessage receiveFromServer = new HandshakeMessage();
        receiveFromServer.recv(socket);
        if (receiveFromServer.getParameter("MessageType").equals("Session")) {
            PrivateKey clientPrivKey = HandshakeCrypto.getPrivateKeyFromKeyFile(privKeyFile);

            byte[] decodedSessionKey = Base64.getDecoder().decode(receiveFromServer.getParameter("SessionKey"));
            byte[] decodedSessionIV = Base64.getDecoder().decode(receiveFromServer.getParameter("SessionIV"));

            sessionKey = HandshakeCrypto.decrypt(decodedSessionKey, clientPrivKey);
            sessionIV = HandshakeCrypto.decrypt(decodedSessionIV, clientPrivKey);

            sessionHost = receiveFromServer.getParameter("ServerHost");
            sessionPort = Integer.valueOf(receiveFromServer.getParameter("ServerPort"));
        } else {
            System.out.println("Receiving Session: Something went wrong - MessageType fail");
        }
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

}
