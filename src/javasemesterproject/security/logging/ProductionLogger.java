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
 * Plain-text logger used in "production" / lower-security environments.
 *
 *  - File: logs/production.log
 *  - Sensitive values are MASKED (first/last char + "***") but not encrypted.
 *  - Intended for monitoring/ops where ops staff need to grep logs without keys.
 *  - Demonstrates the polymorphism in the factory pattern: same {@link Logger}
 *    interface, completely different security posture.
 */
public final class ProductionLogger implements Logger {

    private static final String LOG_FILE = "logs/production.log";
    private static final DateTimeFormatter TS =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS");

    private final Path logPath;
    private final Object writeLock = new Object();

    public ProductionLogger() {
        this.logPath = Paths.get(LOG_FILE);
        ensureFile();
    }

    @Override
    public void logEvent(String category, String message) {
        write("INFO ", category, message);
    }

    @Override
    public void logError(String category, String message, Throwable t) {
        String full = message;
        if (t != null) {
            StringWriter sw = new StringWriter();
            t.printStackTrace(new PrintWriter(sw));
            full = message + " | " + t.getClass().getSimpleName() + ": " + t.getMessage();
        }
        write("ERROR", category, full);
    }

    @Override
    public void logSensitive(String field, String sensitiveValue) {
        write("INFO ", "sensitive." + field, EncryptLogger.mask(sensitiveValue));
    }

    @Override
    public void close() { /* nothing held open */ }

    private void write(String level, String category, String message) {
        String line = LocalDateTime.now().format(TS) + " " + level + " "
                + category + " - " + message + System.lineSeparator();
        synchronized (writeLock) {
            try {
                Files.write(logPath, line.getBytes(StandardCharsets.UTF_8),
                        StandardOpenOption.APPEND);
                System.out.print(line);
            } catch (IOException e) {
                System.err.println("[ProductionLogger] write failed: " + e.getMessage());
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
            }
        } catch (IOException e) {
            throw new IllegalStateException("Cannot initialise log file " + LOG_FILE, e);
        }
    }
}
