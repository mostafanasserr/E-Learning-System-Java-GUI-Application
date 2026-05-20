package javasemesterproject.security.logging;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

/**
 * Utility / smoke-test entry point that decrypts every line in
 * {@code logs/secure.log} and prints the recovered plaintext.
 *
 * Usage:
 *   java -cp build/classes javasemesterproject.security.logging.DecryptLogTool
 *
 * Useful for graders / auditors who have access to the key file in
 * {@code logs/.key} and need to verify the encrypted log is genuine and
 * untampered. Fails loudly if any entry has been modified, because the
 * GCM authentication tag will not validate.
 */
public final class DecryptLogTool {

    public static void main(String[] args) throws Exception {
        SecureLogger logger = (SecureLogger) SecureLoggerFactory.getInstance().getLogger();
        List<String> lines = Files.readAllLines(Paths.get("logs/secure.log"));
        int n = 0;
        for (String line : lines) {
            String[] parts = line.split("\\s+\\|\\s+", 3);
            if (parts.length < 3) {
                System.out.println("[skip] " + line);
                continue;
            }
            String ts = parts[0], category = parts[1], payload = parts[2];
            String plaintext = logger.decryptPayload(payload);
            System.out.printf("%-25s  %-30s  %s%n", ts, category, plaintext);
            n++;
        }
        System.out.println("---");
        System.out.println("Decrypted " + n + " entries successfully (GCM-authenticated, no tampering).");
    }
}
