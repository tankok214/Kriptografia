import javax.net.ssl.*;
import java.io.*;
import java.net.InetSocketAddress;
import java.security.KeyStore;
import java.nio.file.Files;
import java.nio.file.Paths;

public class MITMServer {

    private static final int PORT = 443;  // HTTPS port (requires admin rights on Windows)
    private static final String HTML_FILE = "bnr_homepage.html";
    private static final String KEYSTORE_FILE = "mitm_keystore.jks";
    private static final String KEYSTORE_PASSWORD = "mitm123";

    public static void main(String[] args) {
        // Port parameter optional
        int port = PORT;
        if (args.length > 0) {
            try {
                port = Integer.parseInt(args[0]);
            } catch (NumberFormatException e) {
                System.err.println("Invalid port number. Using default: " + PORT);
            }
        }

        try {
            // Read HTML content
            String htmlContent = readHtmlFile(HTML_FILE);

            // Setup SSL context
            SSLContext sslContext = createSSLContext();
            SSLServerSocketFactory sslServerSocketFactory = sslContext.getServerSocketFactory();

            // Create SSL server socket
            SSLServerSocket serverSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(port);

            System.out.println("=".repeat(80));
            System.out.println("MITM SERVER STARTED");
            System.out.println("=".repeat(80));
            System.out.println("Port: " + port);
            System.out.println("Keystore: " + KEYSTORE_FILE);
            System.out.println();
            System.out.println("IMPORTANT: Set in hosts file:");
            System.out.println("  127.0.0.1  bnr.ro");
            System.out.println();
            System.out.println("Windows hosts file location:");
            System.out.println("  C:\\Windows\\System32\\drivers\\etc\\hosts");
            System.out.println();
            System.out.println("Testing: ping bnr.ro");
            System.out.println();
            System.out.println("Waiting for connections...");
            System.out.println("=".repeat(80));

            // Handle connections
            while (true) {
                try {
                    SSLSocket clientSocket = (SSLSocket) serverSocket.accept();
                    System.out.println("\n[" + new java.util.Date() + "] New connection: " +
                                     clientSocket.getInetAddress().getHostAddress());

                    // Handle client in separate thread
                    new Thread(() -> handleClient(clientSocket, htmlContent)).start();

                } catch (Exception e) {
                    System.err.println("Error handling connection: " + e.getMessage());
                }
            }

        } catch (Exception e) {
            System.err.println("ERROR: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Handle client connection
     */
    private static void handleClient(SSLSocket clientSocket, String htmlContent) {
        try {
            // SSL handshake
            clientSocket.startHandshake();

            // SSL session information
            SSLSession session = clientSocket.getSession();
            System.out.println("  Cipher Suite: " + session.getCipherSuite());
            System.out.println("  Protocol: " + session.getProtocol());

            // Read HTTP request
            BufferedReader in = new BufferedReader(
                new InputStreamReader(clientSocket.getInputStream()));

            String requestLine = in.readLine();
            System.out.println("  Request: " + requestLine);

            // Read HTTP headers (until empty line)
            String line;
            while ((line = in.readLine()) != null && !line.isEmpty()) {
                // Read headers, but don't use them
            }

            // Send HTTP response
            PrintWriter out = new PrintWriter(
                new OutputStreamWriter(clientSocket.getOutputStream()));

            // HTTP status line
            out.println("HTTP/1.1 200 OK");
            out.println("Content-Type: text/html; charset=UTF-8");
            out.println("Content-Length: " + htmlContent.getBytes("UTF-8").length);
            out.println("Server: MITM-BNR-Server");
            out.println("Connection: close");
            out.println(); // Empty line marks end of headers

            // HTML content
            out.println(htmlContent);
            out.flush();

            System.out.println("  Response sent (" + htmlContent.length() + " characters)");

            // Close connection
            clientSocket.close();

        } catch (Exception e) {
            System.err.println("  Error serving client: " + e.getMessage());
        }
    }

    /**
     * Create SSL context from keystore
     */
    private static SSLContext createSSLContext() throws Exception {
        // Load KeyStore
        KeyStore keyStore = KeyStore.getInstance("JKS");

        File keystoreFile = new File(KEYSTORE_FILE);
        if (!keystoreFile.exists()) {
            System.err.println("\nERROR: Keystore file not found: " + KEYSTORE_FILE);
            System.err.println("\nFIRST CREATE THE KEYSTORE:");
            System.err.println("See: openssl_commands.txt for MITM certificate creation");
            System.exit(1);
        }

        try (FileInputStream fis = new FileInputStream(KEYSTORE_FILE)) {
            keyStore.load(fis, KEYSTORE_PASSWORD.toCharArray());
        }

        // Setup KeyManager
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(
            KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, KEYSTORE_PASSWORD.toCharArray());

        // Create SSL context
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), null, null);

        return sslContext;
    }

    /**
     * Read HTML file
     */
    private static String readHtmlFile(String filename) throws IOException {
        File file = new File(filename);
        if (!file.exists()) {
            System.err.println("\nWARNING: HTML file not found: " + filename);
            System.err.println("First run BNRClient to download the content!\n");
            // Return default HTML
            return "<html><body><h1>BNR.ro - MITM Test Page</h1>" +
                   "<p>This is a test page. First run BNRClient!</p></body></html>";
        }

        return new String(Files.readAllBytes(Paths.get(filename)), "UTF-8");
    }
}
