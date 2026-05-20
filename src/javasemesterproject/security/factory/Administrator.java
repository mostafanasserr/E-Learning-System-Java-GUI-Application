package javasemesterproject.security.factory;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import javasemesterproject.security.logging.EncryptLogger;
import javasemesterproject.security.logging.Logger;

/**
 * Administrator — highest privilege level.
 * Full user-management, schema-management, audit access.
 *
 * Because admin actions are sensitive, this subclass overrides
 * {@link #authenticate(String)} to additionally emit an
 * "admin.auth" audit event.
 */
public final class Administrator extends User {

    public Administrator(String username, Logger logger) {
        super(username, logger);
    }

    @Override public String getRole() { return "Administrator"; }

    @Override public DBConnectionProfile getDbProfile() {
        return DBConnectionProfile.FULL_ACCESS;
    }

    @Override public Set<String> getPermissions() {
        Set<String> p = new HashSet<>();
        p.add("user.create");
        p.add("user.delete");
        p.add("user.list");
        p.add("course.delete_any");
        p.add("subject.manage");
        p.add("audit.read");
        p.add("system.configure");
        return Collections.unmodifiableSet(p);
    }

    @Override
    public boolean authenticate(String password) {
        logger.logEvent("admin.auth", "Administrator authentication attempt for "
                + EncryptLogger.mask(username));
        return super.authenticate(password);
    }
}
