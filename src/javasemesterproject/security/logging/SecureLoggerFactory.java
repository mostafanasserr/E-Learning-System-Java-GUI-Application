package javasemesterproject.security.logging;

/**
 * Concrete factory returning a {@link SecureLogger}.
 *
 * Implemented as a thread-safe lazy singleton so all callers
 * (login frames, factory-created users, etc.) share one file handle
 * configuration and one encryption key.
 */
public final class SecureLoggerFactory implements LoggerFactory {

    private static volatile SecureLoggerFactory INSTANCE;
    private final SecureLogger logger;

    private SecureLoggerFactory() {
        this.logger = new SecureLogger();
    }

    public static SecureLoggerFactory getInstance() {
        SecureLoggerFactory ref = INSTANCE;
        if (ref == null) {
            synchronized (SecureLoggerFactory.class) {
                ref = INSTANCE;
                if (ref == null) {
                    INSTANCE = ref = new SecureLoggerFactory();
                }
            }
        }
        return ref;
    }

    @Override
    public Logger getLogger() {
        return logger;
    }
}
