import javax.net.ssl.*;
import java.io.*;
import java.net.URL;
import java.security.cert.*;
import java.security.PublicKey;
import java.text.SimpleDateFormat;
import java.util.Date;

public class BNRClientSecure {

    private static final String OUTPUT_FILE = "bnr_homepage.html";

    // Expected fingerprint of the real bnr.ro certificate (SHA-256)
    // UPDATE THIS after first successful connection to the real server!
    private static final String EXPECTED_FINGERPRINT = "CAPTURE_ON_FIRST_RUN";

    // Expected Common Name pattern for the real server
    private static final String EXPECTED_CN = "bnr.ro";

    // Expected issuer pattern for the real certificate
    private static final String EXPECTED_ISSUER = "certSIGN";

    public static void main(String[] args) {
        try {
            // URL of BNR website (default or from argument)
            String urlString = args.length > 0 ? args[0] : "https://bnr.ro/Home.aspx";
            URL url = new URL(urlString);

            System.out.println("BNR HTTPS Client - Certificate Display");
            System.out.println("Connecting to: " + url);
            System.out.println();

            // Create a trust manager that accepts all certificates (for inspection)
            TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {}
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {}
                }
            };

            // Install the all-trusting trust manager
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

            // Open HTTPS connection
            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            connection.setRequestProperty("User-Agent", "Mozilla/5.0");

            // Set hostname verifier (accepts all for inspection)
            connection.setHostnameVerifier(new CustomHostnameVerifier());

            // Connect (will succeed even with untrusted certs)
            connection.connect();

            // Get server certificates
            Certificate[] certificates = connection.getServerCertificates();

            if (certificates == null || certificates.length == 0) {
                System.err.println("ERROR: No certificates received from server!");
                return;
            }

            X509Certificate serverCert = (X509Certificate) certificates[0];

            // Display certificate information (Task 1 requirement: 10 fields)
            System.out.println("=".repeat(80));
            System.out.println("CERTIFICATE INFORMATION (10 Required Fields)");
            System.out.println("=".repeat(80));

            printCertificateInfo(serverCert);

            // Calculate and display certificate fingerprint
            String actualFingerprint = getCertificateFingerprint(serverCert);
            System.out.println("\n11. Certificate Fingerprint (SHA-256):");
            System.out.println("    " + actualFingerprint);

            System.out.println("\n" + "=".repeat(80));

            // MITM Detection (Tasks 2-3)
            boolean isTrusted = verifyCertificate(serverCert, actualFingerprint);

            if (!isTrusted) {
                System.err.println("\n" + "!".repeat(80));
                System.err.println(" MITM ATTACK DETECTED!");
                System.err.println("!".repeat(80));
                connection.disconnect();
                return;
            }

            System.out.println("\n" + "=".repeat(80));
            System.out.println("CERTIFICATE VERIFICATION: PASSED");
            System.out.println("=".repeat(80));
            System.out.println("The certificate is valid and trusted.");
            System.out.println("Connection is secure.");
            System.out.println("=".repeat(80));

            // Download webpage content (Task 1)
            downloadWebpage(connection);

            connection.disconnect();
            System.out.println("\nConnection closed successfully.");

        } catch (Exception e) {
            System.err.println("An error occurred: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Calculate SHA-256 fingerprint of the certificate
     */
    private static String getCertificateFingerprint(X509Certificate cert) throws Exception {
        java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
        byte[] certBytes = cert.getEncoded();
        byte[] digest = md.digest(certBytes);

        // Convert to hex string with colons
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            sb.append(String.format("%02X", b));
            if (sb.length() < digest.length * 2) {
                sb.append(":");
            }
        }
        return sb.toString();
    }

    /**
     * Extract Common Name from certificate (backward compatibility)
     */
    private static String getCommonName(X509Certificate cert) {
        return extractCN(cert.getSubjectX500Principal().getName());
    }

    /**
     * Print certificate information (10+ fields required by Task 1)
     */
    private static void printCertificateInfo(X509Certificate cert) {
        try {
            SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

            // 1. Subject (Common Name)
            String subject = cert.getSubjectX500Principal().getName();
            System.out.println("1. Subject (Distinguished Name):");
            System.out.println("   " + subject);
            System.out.println("   Common Name (CN): " + extractCN(subject));

            // 2. Issuer
            String issuer = cert.getIssuerX500Principal().getName();
            System.out.println("\n2. Issuer (Certificate Authority):");
            System.out.println("   " + issuer);
            System.out.println("   CA Name: " + extractCN(issuer));

            // 3. Serial Number
            System.out.println("\n3. Serial Number:");
            System.out.println("   " + cert.getSerialNumber().toString(16).toUpperCase());

            // 4. Version
            System.out.println("\n4. Version:");
            System.out.println("   " + cert.getVersion());

            // 5. Validity Period - Not Before
            System.out.println("\n5. Valid From (Not Before):");
            System.out.println("   " + dateFormat.format(cert.getNotBefore()));

            // 6. Validity Period - Not After
            System.out.println("\n6. Valid Until (Not After):");
            System.out.println("   " + dateFormat.format(cert.getNotAfter()));

            // 7. Signature Algorithm
            System.out.println("\n7. Signature Algorithm:");
            System.out.println("   " + cert.getSigAlgName());

            // 8. Public Key Algorithm
            System.out.println("\n8. Public Key Algorithm:");
            System.out.println("   " + cert.getPublicKey().getAlgorithm());

            // 9. Public Key Length
            System.out.println("\n9. Public Key Length:");
            String keyInfo = cert.getPublicKey().toString();
            if (keyInfo.contains("bit")) {
                int start = Math.max(0, keyInfo.indexOf("bit") - 5);
                int end = keyInfo.indexOf("bit") + 3;
                System.out.println("   " + keyInfo.substring(start, end).trim());
            } else {
                System.out.println("   " + cert.getPublicKey().toString().split("\n")[0]);
            }

            // 10. Certificate Type
            System.out.println("\n10. Certificate Type:");
            System.out.println("    " + cert.getType());

        } catch (Exception e) {
            System.err.println("Error displaying certificate info: " + e.getMessage());
        }
    }

    /**
     * Extract Common Name (CN) from Distinguished Name
     */
    private static String extractCN(String dn) {
        String[] parts = dn.split(",");
        for (String part : parts) {
            part = part.trim();
            if (part.startsWith("CN=")) {
                return part.substring(3);
            }
        }
        return "N/A";
    }

    /**
     * Verify certificate authenticity (MITM Detection - Tasks 2-3)
     * Returns true if certificate is trusted, false if MITM attack detected
     */
    private static boolean verifyCertificate(X509Certificate cert, String actualFingerprint) {
        System.out.println("\n" + "=".repeat(80));
        System.out.println("MITM ATTACK DETECTION");
        System.out.println("=".repeat(80));

        boolean allChecksPassed = true;

        // Check 1: Fingerprint verification
        if (!EXPECTED_FINGERPRINT.equals("CAPTURE_ON_FIRST_RUN")) {
            System.out.println("\n[Check 1] Certificate Fingerprint Verification:");
            System.out.println("  Expected: " + EXPECTED_FINGERPRINT);
            System.out.println("  Actual:   " + actualFingerprint);

            if (!actualFingerprint.equals(EXPECTED_FINGERPRINT)) {
                System.out.println("  Status: MISMATCH - ATTACK DETECTED!");
                allChecksPassed = false;
            } else {
                System.out.println("  Status: Match");
            }
        } else {
            System.out.println("\n[Check 1] Certificate Fingerprint:");
            System.out.println("  First run - Recording fingerprint:");
            System.out.println("  " + actualFingerprint);
            System.out.println("\n  UPDATE EXPECTED_FINGERPRINT constant in source code with this value!");
        }

        // Check 2: Common Name verification
        String subject = cert.getSubjectX500Principal().getName();
        String cn = extractCN(subject);

        System.out.println("\n[Check 2] Common Name (CN) Verification:");
        System.out.println("  Expected pattern: *" + EXPECTED_CN + "*");
        System.out.println("  Actual CN:        " + cn);

        if (!cn.toLowerCase().contains(EXPECTED_CN.toLowerCase()) &&
            !cn.equals("*." + EXPECTED_CN)) {
            System.out.println("  Status: MISMATCH - Unexpected CN!");
            allChecksPassed = false;
        } else {
            System.out.println("  Status: Valid");
        }

        // Check 3: Issuer verification
        String issuer = cert.getIssuerX500Principal().getName();

        System.out.println("\n[Check 3] Certificate Issuer Verification:");
        System.out.println("  Expected pattern: *" + EXPECTED_ISSUER + "*");
        System.out.println("  Actual issuer:    " + issuer);

        if (!issuer.contains(EXPECTED_ISSUER)) {
            System.out.println("  Status: UNEXPECTED ISSUER - Self-signed or fake certificate!");
            allChecksPassed = false;
        } else {
            System.out.println("  Status: Valid");
        }

        // Check 4: Validity period
        System.out.println("\n[Check 4] Certificate Validity Period:");
        Date now = new Date();
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

        try {
            cert.checkValidity(now);
            System.out.println("  Status: Certificate is currently valid");
            System.out.println("  Valid from: " + dateFormat.format(cert.getNotBefore()));
            System.out.println("  Valid to:   " + dateFormat.format(cert.getNotAfter()));
        } catch (Exception e) {
            System.out.println("  Status: EXPIRED or NOT YET VALID!");
            allChecksPassed = false;
        }

        return allChecksPassed;
    }

    /**
     * Download webpage content and save to file (Task 1)
     */
    private static void downloadWebpage(HttpsURLConnection connection) {
        try {
            System.out.println("\n" + "=".repeat(80));
            System.out.println("DOWNLOADING WEBPAGE");
            System.out.println("=".repeat(80));

            BufferedReader reader = new BufferedReader(
                new InputStreamReader(connection.getInputStream())
            );

            BufferedWriter writer = new BufferedWriter(
                new FileWriter(OUTPUT_FILE)
            );

            String line;
            int lineCount = 0;

            while ((line = reader.readLine()) != null) {
                writer.write(line);
                writer.newLine();
                lineCount++;
            }

            reader.close();
            writer.close();

            System.out.println("Successfully downloaded " + lineCount + " lines");
            System.out.println("Saved to: " + OUTPUT_FILE);

        } catch (IOException e) {
            System.err.println("Error downloading webpage: " + e.getMessage());
        }
    }

    static class CustomHostnameVerifier implements HostnameVerifier {
        @Override
        public boolean verify(String hostname, SSLSession session) {
            // Accept all - we'll verify manually in verifyCertificate()
            return true;
        }
    }
}
