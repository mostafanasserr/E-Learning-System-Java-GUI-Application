package javasemesterproject.security.factory;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import javasemesterproject.security.logging.Logger;

/**
 * Instructor (Teacher) user — mid privilege level.
 * Can create / update courses they own and grade enrolled students.
 */
public final class Instructor extends User {

    public Instructor(String username, Logger logger) {
        super(username, logger);
    }

    @Override public String getRole() { return "Instructor"; }

    @Override public DBConnectionProfile getDbProfile() {
        return DBConnectionProfile.READ_WRITE;
    }

    @Override public Set<String> getPermissions() {
        Set<String> p = new HashSet<>();
        p.add("course.create");
        p.add("course.update_own");
        p.add("course.delete_own");
        p.add("enrolment.view");
        p.add("grade.assign");
        p.add("profile.view_self");
        p.add("profile.edit_self");
        return Collections.unmodifiableSet(p);
    }
}
