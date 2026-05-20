package javasemesterproject.security.factory;

/**
 * Identifies the privilege level (and therefore the DB credentials)
 * that should be used when a User connects to the database.
 *
 * In a real deployment each profile would map to a distinct MySQL
 * account with GRANTs matching its needs (least-privilege).
 * For this assignment the profile is exposed on every User so the
 * connection code knows how to scope the JDBC URL / credentials.
 */
public enum DBConnectionProfile {

    /** Read-only on own rows + course catalogue. */
    READ_ONLY("elearning_student", "Read access to courses & own profile"),

    /** Read + write on owned course material; read on enrolment. */
    READ_WRITE("elearning_instructor", "Read/write on owned courses & student grades"),

    /** Full DDL/DML — should be used only by admin sessions. */
    FULL_ACCESS("elearning_admin", "Full schema access incl. user management");

    private final String dbUser;
    private final String description;

    DBConnectionProfile(String dbUser, String description) {
        this.dbUser = dbUser;
        this.description = description;
    }

    public String getDbUser()      { return dbUser; }
    public String getDescription() { return description; }
}
