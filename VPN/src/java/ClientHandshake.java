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
import java.security.cert.CertificateEncodingException;
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

    public ClientHandshake(Socket handshakeSocket,String targethost,String targetport,String cacert,String usercert,String clientPrivateKeyFile) throws IOException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException {
        clientHello(handshakeSocket, usercert);
        receiveServerHello(handshakeSocket,cacert);
        sendForward(handshakeSocket,targethost,targetport);
        receiveSession(handshakeSocket,clientPrivateKeyFile);
    }

    public ClientHandshake(Socket handshakeSocket) {
    }

    /**
     * Run client handshake protocol on a handshake socket.
     * Here, we do nothing, for now.
     */


    // Send Client Hello message to the server for the handshake
    public void clientHello(Socket handshakeSocket, String clientCertFile) throws IOException {
        HandshakeMessage sendToServer = new HandshakeMessage();
        try {
            clientCert = VerifyCertificate.getCert(clientCertFile);
        } catch (IOException e) {
            Logger.log("Client Cert Verification Problem");
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        }
        
        try {
            sendToServer.putParameter("MessageType", "ClientHello");
            sendToServer.putParameter("Certificate", VerifyCertificate.encodeCertificate(clientCert));
            System.out.println("Sending client ClientHello");
            sendToServer.send(handshakeSocket);
            Logger.log("ClientHello Send Successfully");
        } catch (CertificateEncodingException e) {
            e.printStackTrace();
            System.out.println("There was a problem with the ClientHello message");
        }

        Logger.log("ClientHello msg sent to: " + handshakeSocket);

    }

    // Receive server hello + cert from the server
    public void receiveServerHello(Socket handshakeSocket, String caCert) throws IOException {
        String expectedDN = "CN=server-pf.ik2206.kth.se";
        HandshakeMessage receiveFromServer = new HandshakeMessage();
        try {
            receiveFromServer.recv(handshakeSocket);
        } catch (IOException e) {
            Logger.log("There was a problem with receiving a ServerHello message");
            e.printStackTrace();
        }
        if (receiveFromServer.getParameter("MessageType").equals("ServerHello")) {
            try {
                VerifyCertificate.getVerifyCaUser(caCert,receiveFromServer.getParameter("Certificate"), expectedDN);

            } catch (Exception e) {
                e.printStackTrace();
            }
            try {
                serverCert = VerifyCertificate.decodeCert(receiveFromServer.getParameter("Certificate"));
            } catch (CertificateException e) {
                Logger.log("There was a problem with the Server Cert");
                e.printStackTrace();
            }
            Logger.log("Verify succeeded");
            Logger.log("Server cert verification successful.");
        } else {
            System.out.println("Receiving ServerHello: Something went wrong - MessageType fail");
            handshakeSocket.close();
        }
    }

    public void sendForward(Socket handshakeSocket, String targetHost, String targetPort) throws IOException {
        HandshakeMessage sendToServer = new HandshakeMessage();
        sendToServer.putParameter("MessageType", "Forward");
        sendToServer.putParameter("TargetHost", targetHost);
        sendToServer.putParameter("TargetPort", targetPort);
        sendToServer.send(handshakeSocket);
        Logger.log("Forward Message sent to " + handshakeSocket);

    }

    public void receiveSession(Socket handshakeSocket, String privKeyFile) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException {
        try {
        HandshakeMessage receiveFromServer = new HandshakeMessage();
        receiveFromServer.recv(handshakeSocket);
        if (receiveFromServer.getParameter("MessageType").equals("Session")) {
            PrivateKey clientPrivKey = HandshakeCrypto.getPrivateKeyFromKeyFile(privKeyFile);

            byte[] decodedSessionKey = Base64.getDecoder().decode(receiveFromServer.getParameter("SessionKey"));
            byte[] decodedSessionIV = Base64.getDecoder().decode(receiveFromServer.getParameter("SessionIV"));

            sessionKey = HandshakeCrypto.decrypt(decodedSessionKey, clientPrivKey);
            sessionIV = HandshakeCrypto.decrypt(decodedSessionIV, clientPrivKey);

            sessionHost = receiveFromServer.getParameter("SessionHost");
            sessionPort = Integer.parseInt(receiveFromServer.getParameter("SessionPort"));
        } else {
            System.out.println("Receiving Session: Something went wrong - MessageType fail");
        }
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

}
