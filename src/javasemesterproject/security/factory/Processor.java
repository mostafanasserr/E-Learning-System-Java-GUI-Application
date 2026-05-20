package javasemesterproject.security.factory;

import javasemesterproject.security.logging.Logger;
import javasemesterproject.security.logging.LoggerFactory;
import javasemesterproject.security.logging.ProductionLoggerFactory;
import javasemesterproject.security.logging.SecureLoggerFactory;

/**
 * The "client" half of the secure-factory pattern.
 *
 *  - Chooses which {@link LoggerFactory} to use based on a {@link SecurityLevel}.
 *  - Creates concrete {@link User} subclasses ({@link Student},
 *    {@link Instructor}, {@link Administrator}) on demand.
 *  - Hands each user the chosen Logger so every subsequent action they
 *    perform is auditable through the same channel.
 *
 * Why a separate "Processor"?
 *   The textbook (Mark Dowd, "The Art of Software Security Assessment",
 *   §11 — Secure Factories) keeps the factory selection logic out of the
 *   product classes so neither side knows which logger they are dealing
 *   with. Processor is that selection layer.
 */
public final class Processor {

    public enum Role {
        STUDENT, INSTRUCTOR, ADMINISTRATOR
    }

    public enum SecurityLevel {
        /** Strong confidentiality — entries encrypted on disk. */
        SECURE,
        /** Operational logging — masked sensitive values, no encryption. */
        PRODUCTION
    }

    private final LoggerFactory loggerFactory;

    public Processor(SecurityLevel level) {
        switch (level) {
            case SECURE:
                this.loggerFactory = SecureLoggerFactory.getInstance();
                break;
            case PRODUCTION:
                this.loggerFactory = ProductionLoggerFactory.getInstance();
                break;
            default:
                throw new IllegalArgumentException("Unknown level " + level);
        }
    }

    /** Construct the right concrete user for a role, wired to the chosen logger. */
    public User createUser(Role role, String username) {
        Logger logger = loggerFactory.getLogger();
        logger.logEvent("user.create", "role=" + role + " username="
                + javasemesterproject.security.logging.EncryptLogger.mask(username));

        switch (role) {
            case STUDENT:       return new Student(username, logger);
            case INSTRUCTOR:    return new Instructor(username, logger);
            case ADMINISTRATOR: return new Administrator(username, logger);
            default:
                throw new IllegalArgumentException("Unknown role " + role);
        }
    }

    public Logger getLogger() {
        return loggerFactory.getLogger();
    }

    // -----------------------------------------------------------------
    // Demo / smoke-test entry point so a grader can run the factory
    // without launching MySQL / the Swing GUI:
    //
    //     javac -d build/classes $(find src -name "*.java")
    //     java  -cp build/classes javasemesterproject.security.factory.Processor
    //
    // After running, inspect:
    //   logs/secure.log       (encrypted lines)
    //   logs/production.log   (plain, masked lines)
    // -----------------------------------------------------------------
    public static void main(String[] args) {
        System.out.println("=== Secure Factory Pattern Demo ===");

        // ---- SECURE path ---------------------------------------------------
        Processor secureProc = new Processor(SecurityLevel.SECURE);
        User student = secureProc.createUser(Role.STUDENT,       "alice");
        User teacher = secureProc.createUser(Role.INSTRUCTOR,    "bob_teacher");
        User admin   = secureProc.createUser(Role.ADMINISTRATOR, "root_admin");

        for (User u : new User[]{student, teacher, admin}) {
            System.out.println(" * created " + u
                    + " -> dbUser=" + u.getDbProfile().getDbUser()
                    + " permissions=" + u.getPermissions().size());
            u.authenticate("SuperSecret!2026");   // value will be encrypted in log
        }

        // ---- PRODUCTION path -----------------------------------------------
        Processor prodProc = new Processor(SecurityLevel.PRODUCTION);
        User prodStudent = prodProc.createUser(Role.STUDENT, "charlie");
        prodStudent.authenticate("hunter2");      // value will be MASKED in log
        prodProc.getLogger().logError("startup",
                "demo finished — production logger active",
                new RuntimeException("synthetic error for demo"));

        System.out.println();
        System.out.println("Done. Inspect logs/secure.log (encrypted) "
                + "and logs/production.log (masked).");
    }
}
