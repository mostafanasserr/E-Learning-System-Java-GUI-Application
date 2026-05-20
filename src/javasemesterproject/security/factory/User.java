package javasemesterproject.security.factory;

import java.util.Set;
import javasemesterproject.security.logging.Logger;

/**
 * Abstract product of the {@link Processor} factory.
 *
 * Each concrete subclass advertises:
 *   - its role name
 *   - its DB connection profile (least-privilege)
 *   - the set of high-level permissions it grants
 *
 * Holds a reference to the {@link Logger} chosen by the factory client
 * so every privileged action is auditable.
 */
public abstract class User {

    protected final String username;
    protected final Logger logger;

    protected User(String username, Logger logger) {
        if (username == null || username.isEmpty()) {
            throw new IllegalArgumentException("username required");
        }
        if (logger == null) {
            throw new IllegalArgumentException("logger required");
        }
        this.username = username;
        this.logger   = logger;
    }

    public final String getUsername() { return username; }

    public abstract String getRole();
    public abstract DBConnectionProfile getDbProfile();
    public abstract Set<String> getPermissions();

    /**
     * Authenticate this user. Real auth would hit the DB with a hashed
     * password lookup using {@link #getDbProfile()}'s credentials —
     * here we keep the surface minimal and just audit the attempt.
     */
    public boolean authenticate(String password) {
        logger.logEvent("auth.attempt",
                "role=" + getRole() + " user=" + javasemesterproject.security.logging.EncryptLogger.mask(username));
        logger.logSensitive("password." + getRole().toLowerCase(), password);
        // Subclasses can override with actual credential validation logic.
        return password != null && !password.isEmpty();
    }

    @Override
    public String toString() {
        return getRole() + "(" + username + ", dbProfile=" + getDbProfile() + ")";
    }
}
