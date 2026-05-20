package javasemesterproject.security.factory;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import javasemesterproject.security.logging.Logger;

/**
 * Student user — lowest privilege level.
 * Can browse the catalogue, enrol in courses, and view their own profile.
 *
 * NOTE: deliberately not in the same package as the existing
 * {@code javasemesterproject.Student.Student} Swing dashboard class — this
 * is the abstract factory product, not the JFrame.
 */
public final class Student extends User {

    public Student(String username, Logger logger) {
        super(username, logger);
    }

    @Override public String getRole() { return "Student"; }

    @Override public DBConnectionProfile getDbProfile() {
        return DBConnectionProfile.READ_ONLY;
    }

    @Override public Set<String> getPermissions() {
        Set<String> p = new HashSet<>();
        p.add("course.view");
        p.add("course.enrol");
        p.add("course.withdraw");
        p.add("profile.view_self");
        p.add("profile.edit_self");
        p.add("message.send");
        return Collections.unmodifiableSet(p);
    }
}
