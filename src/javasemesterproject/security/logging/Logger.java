package javasemesterproject.security.logging;

/**
 * Common interface implemented by every logger the factory can produce.
 *
 * Two concrete implementations exist:
 *   - {@link SecureLogger}     – encrypts entries and writes to logs/secure.log
 *   - {@link ProductionLogger} – plain entries, writes to logs/production.log
 *
 * Methods accept a "category" so callers can distinguish auth events, errors, etc.
 */
public interface Logger {

    /** Log a non-sensitive event (e.g. "login_attempt", "course_enrolled"). */
    void logEvent(String category, String message);

    /** Log an error, optionally with a Throwable. */
    void logError(String category, String message, Throwable t);

    /**
     * Log a sensitive value (password, full email, session token, etc.).
     * Implementations MUST NOT write the raw value in cleartext to disk —
     * SecureLogger encrypts via {@link EncryptLogger}.
     */
    void logSensitive(String field, String sensitiveValue);

    /** Flush + close any underlying streams. */
    void close();
}
