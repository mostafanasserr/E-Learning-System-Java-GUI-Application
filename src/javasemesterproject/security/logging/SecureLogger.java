package javasemesterproject.security.logging;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Logger that encrypts every entry before writing to disk.
 *
 *  - File: logs/secure.log  (created with rw------- where supported)
 *  - Each line:  <timestamp> | <category> | <encrypted-payload>
 *      where <encrypted-payload> is produced by {@link EncryptLogger}.
 *  - Sensitive values (passwords, full emails) MUST be logged via
 *    {@link #logSensitive(String, String)} which guarantees encryption.
 *  - Non-sensitive identifiers (e.g. masked username) are still encrypted
 *    because the entire payload section is encrypted — only the timestamp
 *    and category are left in the clear so an operator can grep for
 *    "login_failure" without first decrypting.
 *
 * Thread-safety: writes are serialised on a private monitor; appends to
 * the file use StandardOpenOption.APPEND so the OS guarantees atomic
 * single-write append on POSIX systems.
 */
public final class SecureLogger implements Logger {

    private static final String LOG_FILE   = "logs/secure.log";
    private static final DateTimeFormatter TS =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS");

    private final EncryptLogger crypto;
    private final Path logPath;
    private final Object writeLock = new Object();

    public SecureLogger() {
        this.crypto  = new EncryptLogger();
        this.logPath = Paths.get(LOG_FILE);
        ensureFile();
    }

    @Override
    public void logEvent(String category, String message) {
        writeEncrypted(category, "EVENT", message);
    }

    @Override
    public void logError(String category, String message, Throwable t) {
        String full = message;
        if (t != null) {
            StringWriter sw = new StringWriter();
            t.printStackTrace(new PrintWriter(sw));
            full = message + " | exception=" + t.getClass().getSimpleName()
                    + ": " + t.getMessage() + " | stack=" + sw.toString().replace('\n', ' ');
        }
        writeEncrypted(category, "ERROR", full);
    }

    @Override
    public void logSensitive(String field, String sensitiveValue) {
        String safeValue = sensitiveValue == null ? "<null>" : sensitiveValue;
        writeEncrypted("sensitive." + field, "SENSITIVE", safeValue);
    }

    @Override
    public void close() {
        /* nothing held open — every append re-opens the file */
    }

    /** Convenience: decrypt a previously-written encrypted payload (for audit/grading). */
    public String decryptPayload(String encryptedPayload) {
        return crypto.decrypt(encryptedPayload);
    }

    // -----------------------------------------------------------------

    private void writeEncrypted(String category, String level, String payload) {
        String body = "level=" + level + "|payload=" + payload;
        String encrypted = crypto.encrypt(body);
        String line = LocalDateTime.now().format(TS) + " | " + category + " | " + encrypted
                + System.lineSeparator();

        synchronized (writeLock) {
            try {
                Files.write(logPath, line.getBytes(StandardCharsets.UTF_8),
                        StandardOpenOption.APPEND);
            } catch (IOException e) {
                System.err.println("[SecureLogger] write failed: " + e.getMessage());
            }
        }
    }

    private void ensureFile() {
        try {
            Path parent = logPath.getParent();
            if (parent != null && !Files.exists(parent)) {
                Files.createDirectories(parent);
            }
            if (!Files.exists(logPath)) {
                Files.createFile(logPath);
                try {
                    Files.setPosixFilePermissions(logPath,
                            java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
                } catch (UnsupportedOperationException ignored) {
                    // Windows path — apply ACL manually.
                }
            }
        } catch (IOException e) {
            throw new IllegalStateException("Cannot initialise log file " + LOG_FILE, e);
        }
    }
}
