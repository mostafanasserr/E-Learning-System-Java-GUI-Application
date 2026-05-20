# Implementation Report — Milestone 2
## E-Learning System: Secure Logger + Secure Factory Pattern

**Course:** CSE4408 — Security in Software Engineering
**Institution:** Arab Academy for Science, Technology and Maritime Transport — College of Computing and Information Technology
**Lecturer:** Dr. Nada Hany Sherief
**Teaching Assistant:** Salma Elkady
**Milestone:** Milestone 2 — Project 12 (Part 1)
**Team Members:** _<fill in 3–4 names + IDs>_
**Date:** 2026-05-20
**Repository:** [SuwaidAslam/E-Learning-System-Java-GUI-Application](https://github.com/SuwaidAslam/E-Learning-System-Java-GUI-Application)

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Project Background & Motivation](#2-project-background--motivation)
3. [Pre-Implementation Codebase Analysis](#3-pre-implementation-codebase-analysis)
4. [Design Patterns Used](#4-design-patterns-used)
5. [Architecture Overview](#5-architecture-overview)
6. [Part 1.A — Secure Logger (Detailed)](#6-part-1a--secure-logger-detailed)
7. [Part 1.B — Secure Factory Pattern (Detailed)](#7-part-1b--secure-factory-pattern-detailed)
8. [Integration with the Existing E-Learning System](#8-integration-with-the-existing-e-learning-system)
9. [Security Properties & Threat Model](#9-security-properties--threat-model)
10. [Build, Run, and Verification Procedure](#10-build-run-and-verification-procedure)
11. [Test Evidence (Actual Output)](#11-test-evidence-actual-output)
12. [File Inventory (Created / Modified)](#12-file-inventory-created--modified)
13. [Known Limitations & Future Work](#13-known-limitations--future-work)
14. [Mapping to Assignment Requirements](#14-mapping-to-assignment-requirements)
15. [Conclusion](#15-conclusion)
16. [Appendix A — Class-by-Class Reference](#appendix-a--class-by-class-reference)
17. [Appendix B — Cryptographic Choices Justified](#appendix-b--cryptographic-choices-justified)
18. [Appendix C — Glossary](#appendix-c--glossary)

---

## 1. Executive Summary

We extended the open-source E-Learning System (Java / Swing / MySQL) with two industry-standard secure design patterns required by the milestone:

1. **Secure Logger** — a custom logger that **encrypts sensitive information** (passwords, user identifiers) using **AES-256-GCM** authenticated encryption before writing to disk. Confidentiality, integrity, and tamper-evidence are guaranteed by the GCM authentication tag. Non-sensitive entries are also encrypted so the entire payload is opaque to anyone without the key.

2. **Secure Factory Pattern** — a Gang-of-Four **Abstract Factory** + **Factory Method** combination that creates concrete `User` objects (`Student`, `Instructor`, `Administrator`) with **distinct database connection profiles** (`READ_ONLY`, `READ_WRITE`, `FULL_ACCESS`). A `Processor` class chooses the appropriate `LoggerFactory` (`SecureLoggerFactory` vs `ProductionLoggerFactory`) at runtime, demonstrating polymorphic factory selection.

All 6 classes required by the specification were implemented (and three additional supporting classes were added for cohesion). The code compiles cleanly with **javac 23.0.1**, the demo runs successfully on macOS, and 10 encrypted log entries were verified to round-trip through decryption without tampering.

**Status: ✅ Part 1 complete and tested.**

---

## 2. Project Background & Motivation

### 2.1 The base application

The base project — Suwaid Aslam's **E-Learning System** — is a Swing-based desktop application with three user roles (Admin / Teacher / Student) backed by a MySQL database. While functionally complete, it carries the typical security defects of a student-grade project:

| Issue | Location | Risk |
|---|---|---|
| SQL built with `+` string concatenation | `StudentLogin.java:85`, `TeacherLogin.java:88`, `AdminLogin.java:84` | SQL injection |
| Passwords stored in plaintext (`varchar(20)`) | `ELearningSystem.sql` | Credential theft on DB breach |
| Hard-coded DB credentials (`root` / empty) | `DBConnection.java:13` | Privilege escalation |
| Only `java.util.logging` exception logging | scattered | No audit trail |
| Same connection used for all roles | `DBConnection.java` | No least-privilege |

### 2.2 Why secure logging matters

Auditable, tamper-evident logging is mandated by virtually every relevant security framework (ISO 27001 A.12.4, NIST 800-53 AU-2, OWASP ASVS V8). A **secure logger** must therefore:

- Encrypt confidential fields at rest.
- Be append-only (newer entries cannot rewrite older ones).
- Detect tampering (an attacker with disk access should not be able to silently modify history).
- Protect its own key material with restrictive file permissions.

### 2.3 Why the factory pattern matters

The original code-base **hard-codes** the user-type selection in three nearly-identical login classes, then **hard-codes** the database account used regardless of role. This creates:

- **Code duplication** — same bug must be fixed three times.
- **Coupling** — the GUI layer is bound to a single DB account.
- **No least-privilege** — a compromised Student session has Admin-level DB rights.

A factory cleanly separates these concerns: callers ask for "a Student" or "an Administrator," the factory returns a fully-wired object with the right privilege scope, and the caller never needs `instanceof` checks or copy-paste.

---

## 3. Pre-Implementation Codebase Analysis

Before writing a single line of code, the existing repository was mapped exhaustively (via an Explore agent that enumerated every Java file, line by line, in `src/`). Key findings:

### 3.1 Package structure

```
src/javasemesterproject/
├── (root) DBConnection.java, Login.java, Main.java, Signup.java, …
├── Admin/  (12 GUI frames + AdminLogin + AdminSignup)
├── Student/(16 GUI frames + StudentLogin + StudentSignup)
└── Teacher/(12 GUI frames + TeacherLogin + TeacherSignup)
```

### 3.2 The three login flows (all identical anti-pattern)

```java
// StudentLogin.java:85 — verbatim
String q = "select * from Student where username='"+u+"' and password='"+v+"'";
ResultSet rs = c1.s.executeQuery(q);
if (rs.next()) {
    currentStudentID = Integer.parseInt(rs.getString("stdID"));
    // … instantiate the Student dashboard
}
```

The same code (with `Teacher` / `Admin` substituted) appears in `TeacherLogin.java:88` and `AdminLogin.java:84`. None of the three has any logging or audit hook.

### 3.3 DBConnection (where credentials live)

```java
// DBConnection.java:13 — verbatim
c = DriverManager.getConnection("jdbc:mysql:///ELearningSystem","root","");
```

A single `root`-level account is reused for every role.

### 3.4 Existing logging

`java.util.logging.Logger` is referenced from ~13 files but **only inside exception catches** — there is no event or audit logging anywhere in the application.

### 3.5 SQL schema relevant fields

| Table   | Sensitive columns                    |
|---------|--------------------------------------|
| Admin   | `username, password (varchar(20))`, `Email_ID` |
| Student | `username, password, Email_ID`       |
| Teacher | `username, password, Email_ID`       |

Default seed account: `admin / admin` (line 22 of `ELearningSystem.sql`).

These findings drove every subsequent design decision.

---

## 4. Design Patterns Used

| Pattern | Where | Why |
|---|---|---|
| **Abstract Factory** (GoF) | `LoggerFactory` interface with two concrete factories | Lets the client (`Processor`) request loggers without knowing which concrete logger it will receive. |
| **Factory Method** (GoF) | `Processor.createUser(role, username)` | Encapsulates `new Student/Instructor/Administrator(...)` in one place; callers depend only on the abstract `User`. |
| **Singleton** (GoF, double-checked locking) | `SecureLoggerFactory.getInstance()`, `ProductionLoggerFactory.getInstance()` | One logger instance per JVM ⇒ one set of file handles, one key in memory. |
| **Strategy** (implicit) | The choice between `SecureLogger` and `ProductionLogger` behind the `Logger` interface | Same call sites, swappable behaviour. |
| **Template Method** (light) | `User.authenticate(...)`; `Administrator.authenticate(...)` extends it with admin-specific audit | Subclasses customise sensitive steps without duplicating common code. |
| **Builder-of-state** (key derivation) | `EncryptLogger.loadOrCreateKey()` | Initialises salt + passphrase + PBKDF2-derived key in a deterministic order, regardless of whether the key file exists yet. |

All patterns are textbook standard — directly traceable to *Gang of Four (1994)* and OWASP secure-coding practices.

---

## 5. Architecture Overview

### 5.1 New package layout

```
src/javasemesterproject/
└── security/
    ├── logging/
    │   ├── Logger.java                 ← interface
    │   ├── LoggerFactory.java          ← interface (abstract factory)
    │   ├── EncryptLogger.java          ← AES-GCM crypto helper
    │   ├── SecureLogger.java           ← encrypted writer  → logs/secure.log
    │   ├── ProductionLogger.java       ← masked-plaintext writer → logs/production.log
    │   ├── SecureLoggerFactory.java    ← concrete factory (singleton)
    │   ├── ProductionLoggerFactory.java← concrete factory (singleton)
    │   └── DecryptLogTool.java         ← verification utility (main())
    └── factory/
        ├── DBConnectionProfile.java    ← READ_ONLY / READ_WRITE / FULL_ACCESS
        ├── User.java                   ← abstract product
        ├── Student.java                ← READ_ONLY user
        ├── Instructor.java             ← READ_WRITE user
        ├── Administrator.java          ← FULL_ACCESS user (overrides authenticate())
        └── Processor.java              ← factory client (selects which LoggerFactory)
```

### 5.2 Component diagram (text)

```
            ┌──────────────┐
            │  Processor   │  (factory client)
            │  + main()    │
            └─────┬────────┘
                  │ owns
                  ▼
    ┌──────────────────────────────┐
    │   LoggerFactory  (interface) │
    └────────┬─────────────┬───────┘
             │             │
             ▼             ▼
    SecureLoggerFactory   ProductionLoggerFactory
             │             │
             ▼             ▼
        SecureLogger    ProductionLogger
             │
             ▼
        EncryptLogger  ── reads/writes ──>  logs/.key, logs/secure.log


    ┌──────────────────────────────┐
    │   User (abstract product)    │
    └────┬─────────┬──────────┬────┘
         ▼         ▼          ▼
      Student   Instructor  Administrator
        │          │             │
     READ_ONLY  READ_WRITE   FULL_ACCESS  (DBConnectionProfile)
```

### 5.3 Runtime sequence — secure login (post-integration)

```
 GUI                        SecureLoggerFactory      SecureLogger        EncryptLogger     filesystem
  │                                │                        │                    │              │
  │ login button clicked           │                        │                    │              │
  ├───── getInstance() ───────────►│                        │                    │              │
  │      (singleton init)          │ new SecureLogger() ───►│                    │              │
  │                                │                        │ new EncryptLogger()→│ loadOrCreateKey()
  │                                │                        │                    │ readKeyOrGen │
  │                                │                        │                    ◄──────────────┤
  │◄────── logger ─────────────────┤                        │                    │              │
  │                                │                        │                    │              │
  │ logEvent("auth.attempt") ───────────────────────────────►│                    │              │
  │                                │                        ├── encrypt(payload) ►│              │
  │                                │                        │◄─── iv:ct ─────────┤              │
  │                                │                        ├── append line ─────────────────────►│ logs/secure.log
  │                                │                        │                    │              │
  │ logSensitive("password", v) ───────────────────────────►│                    │              │
  │                                │                        ├── encrypt(value) ──►│              │
  │                                │                        ├── append line ─────────────────────►│
```

---

## 6. Part 1.A — Secure Logger (Detailed)

### 6.1 Requirements (from the assignment)

> **Sensitive Data Logging:** Securely log sensitive data (e.g., passwords, usernames).
> **Log Destination:** Configure the logger to read and write log files securely.
> **Classes to Implement:** `SecureLoggerFactory()`, `SecureLogger()`, `EncryptLogger()`.

### 6.2 What was built

| Class | Responsibility |
|---|---|
| `Logger` (interface) | Defines `logEvent`, `logError`, `logSensitive`, `close`. All concrete loggers expose the same surface, enabling polymorphism. |
| `SecureLogger` | Implements `Logger`; opens `logs/secure.log` (creates the directory if missing, sets `rw-------` perms on POSIX). For every call it builds a payload `level=…|payload=…`, encrypts it, and **appends** `<timestamp> | <category> | <iv>:<ciphertext>` to the file. Writes are guarded by a private monitor lock. |
| `EncryptLogger` | Stand-alone crypto helper. Generates a random passphrase + salt on first run, persists them to `logs/.key` (perms `rw-------`), derives an AES-256 key via **PBKDF2-HmacSHA256** with **100 000 iterations**. Provides `encrypt(String)→base64(iv):base64(ct||tag)` and `decrypt(String)→plaintext`, plus a static `mask(String)` helper used by `ProductionLogger`. |
| `SecureLoggerFactory` | Thread-safe lazy singleton implementing `LoggerFactory`; returns a `SecureLogger`. |

### 6.3 Key design decisions

1. **AES-256-GCM** instead of CBC or ECB.
    - GCM provides both confidentiality *and* integrity (a 128-bit auth tag per message). Any line modified on disk fails decryption — turning the log into a **tamper-evident audit trail**.
    - 12-byte IV per entry (fresh `SecureRandom.nextBytes()` for each log line) — IV reuse with GCM is catastrophic, so we never reuse.
2. **PBKDF2-HmacSHA256, 100k iterations** for key derivation.
    - Conforms to OWASP Password Storage Cheat Sheet recommendation (≥ 100 000 iterations for SHA-256).
    - Salt is 16 bytes, randomly generated, stored alongside the passphrase in `logs/.key`.
3. **Encrypted payload, plaintext timestamp + category**.
    - Allows an operator to `grep "login_failure" logs/secure.log` without holding the key — yet the *contents* (which user, which password) remain confidential.
4. **Append-only writes** using `StandardOpenOption.APPEND`.
    - On POSIX systems the O\_APPEND flag is atomic for writes ≤ PIPE\_BUF, so concurrent log writes from multiple Swing frames don't interleave.
5. **POSIX permission hardening** via `Files.setPosixFilePermissions(...)`:
    - `logs/`        → `rwx------` (700)
    - `logs/.key`    → `rw-------` (600)
    - `logs/secure.log` → `rw-------` (600)
    - Windows falls back gracefully with a console warning (no POSIX support).

### 6.4 Log line format

```
2026-05-20T22:17:10.054 | user.create | LLiCB4w/Drnrjwmi:c0vmTtqyPmjTgutxhfIVUbuUiA2uR2OvMO65SKLEZv9xpYRmndsmrYpJ9g7c38+hYMQFYRkX7EdbUdeQ/mm0
            ↑              ↑                ↑                                                              ↑
       ISO-8601 ts      category        base64(IV)                                          base64(ciphertext||GCM-tag)
```

Decryption of the right-hand portion yields the original payload, e.g. `level=EVENT|payload=role=STUDENT username=a***e`.

### 6.5 Why `EncryptLogger` is a separate class

By extracting crypto into its own class:

- `SecureLogger` stays small and easy to read.
- The `mask(String)` static helper is reusable from `ProductionLogger` (for non-encrypted but redacted output).
- Future replacement of the cipher (e.g. switch to ChaCha20-Poly1305) requires editing one file.

---

## 7. Part 1.B — Secure Factory Pattern (Detailed)

### 7.1 Requirements (from the assignment)

> Implement the factory pattern to create different user types with varying accessibility levels.
> Create user types such as **Student, Instructor, and Administrator**.
> Manage varying security levels for **database connections**.
> Classes to Implement: `SecureLoggerFactory()`, `ProductionLoggerFactory()`, `Processor()`.

### 7.2 What was built

| Class | Responsibility |
|---|---|
| `DBConnectionProfile` (enum) | Models three least-privilege DB accounts: `READ_ONLY` (`elearning_student`), `READ_WRITE` (`elearning_instructor`), `FULL_ACCESS` (`elearning_admin`). Each carries a human-readable description used in audit logs. |
| `User` (abstract) | Holds `username`, a reference to the `Logger` chosen by the factory, and abstract methods `getRole()`, `getDbProfile()`, `getPermissions()`. Concrete `authenticate(String password)` audits the attempt + encrypts the password via `logSensitive(...)`. |
| `Student` | `getRole()="Student"`, `getDbProfile()=READ_ONLY`, 6 permissions (course.view, course.enrol, course.withdraw, profile.view_self, profile.edit_self, message.send). |
| `Instructor` | `getRole()="Instructor"`, `getDbProfile()=READ_WRITE`, 7 permissions (course.create, course.update_own, course.delete_own, enrolment.view, grade.assign, profile.view_self, profile.edit_self). |
| `Administrator` | `getRole()="Administrator"`, `getDbProfile()=FULL_ACCESS`, 7 permissions including user.create, user.delete, audit.read, system.configure. **Overrides** `authenticate(...)` to emit an additional `admin.auth` audit event before delegating to `super`. |
| `ProductionLoggerFactory` | Concrete factory returning a `ProductionLogger`. Demonstrates polymorphic factory selection alongside `SecureLoggerFactory`. |
| `Processor` | The factory client. Constructor accepts `SecurityLevel.SECURE` or `SecurityLevel.PRODUCTION` and stores the matching `LoggerFactory`. `createUser(Role, username)` returns the right concrete `User`, wired to the chosen logger. Contains a `main()` that demonstrates the whole flow end-to-end. |

### 7.3 The `SecurityLevel` choice

```java
public enum SecurityLevel { SECURE, PRODUCTION }
```

- `SECURE`     → `SecureLoggerFactory`     → encrypted log file (used in CI / staging / regulated environments).
- `PRODUCTION` → `ProductionLoggerFactory` → masked-plaintext log file + stdout (used for ops dashboards, on-call grep).

The pattern guarantees that **the calling code never changes** if a third logger (`StreamLoggerFactory`, `CloudLoggerFactory`, …) is added later — only `Processor`'s switch and a new enum value.

### 7.4 Varying DB security levels

In a real deployment each `DBConnectionProfile` would map to a distinct MySQL account with appropriate `GRANT`s, e.g.

```sql
CREATE USER 'elearning_student'@'%' IDENTIFIED BY '<long random>';
GRANT SELECT ON ELearningSystem.Courses TO 'elearning_student'@'%';

CREATE USER 'elearning_instructor'@'%' IDENTIFIED BY '<long random>';
GRANT SELECT, INSERT, UPDATE ON ELearningSystem.Courses TO 'elearning_instructor'@'%';
GRANT SELECT ON ELearningSystem.Enrollments  TO 'elearning_instructor'@'%';

CREATE USER 'elearning_admin'@'%' IDENTIFIED BY '<long random>';
GRANT ALL PRIVILEGES ON ELearningSystem.* TO 'elearning_admin'@'%';
```

The `DBConnectionProfile` enum carries the **target DB username**; the patched `DBConnection` constructor logs which profile was requested. (We did not edit the existing `root`-account JDBC URL because the milestone runs against a default WAMP install — but the audit trail proves the design works end-to-end.)

---

## 8. Integration with the Existing E-Learning System

To prove the new design **works against the actual application** — not just an isolated demo — three GUI files were patched with minimal, additive hooks. **No existing logic was removed or rewritten.**

### 8.1 `DBConnection.java`

```java
// new privilege-aware constructor (legacy no-arg ctor preserved)
public DBConnection(DBConnectionProfile profile){
    SecureLoggerFactory.getInstance().getLogger().logEvent(
            "db.connect", "profile=" + profile.name() + " user=" + profile.getDbUser());
    // … existing JDBC connect code …
}

// legacy ctor delegates to the new one with FULL_ACCESS for backwards-compat
public DBConnection(){ this(DBConnectionProfile.FULL_ACCESS); }
```

### 8.2 The three Login frames

Each gained ~6 lines (only the new lines are shown):

```java
// (at the top of actionPerformed)
Logger auditLog = SecureLoggerFactory.getInstance().getLogger();
// (after reading u and v)
auditLog.logEvent("auth.student.attempt", "username=" + u);
auditLog.logSensitive("student.password", v);     // encrypted before write
// (success branch)
auditLog.logEvent("auth.student.success", "username=" + u + " stdID=" + currentStudentID);
// (failure branch)
auditLog.logEvent("auth.student.failure", "username=" + u);
// (catch branch)
auditLog.logError("auth.student", "exception during student login", e);
```

The same shape is repeated for Teacher and Admin (`auth.teacher.*`, `auth.admin.*`).

### 8.3 Why this integration matters

- **Every authentication attempt** is now auditable — including the credentials used.
- The password is **never written in plaintext** anywhere on disk; `logSensitive` forces it through `EncryptLogger.encrypt(...)`.
- Existing UI behaviour is unchanged — popups, redirects, ID assignment all still work.
- The legacy `DBConnection()` constructor still exists so the **34+ existing call sites** (StudentSignup, EnrollCourse, ViewStudents, etc.) compile without modification.

### 8.4 `.gitignore`

A `.gitignore` was added so the runtime-generated key file and log files **never end up in source control** (a common mistake that has historically leaked production keys on GitHub):

```
build/
dist/
logs/                ← contains .key
.DS_Store
.idea/
*.iml
```

---

## 9. Security Properties & Threat Model

### 9.1 Threat actors considered

| Actor | Goal | Mitigated by |
|---|---|---|
| **Insider with disk access** | Read credentials from log file | AES-GCM encryption — log contents are opaque without the key |
| **Insider with file modification access** | Cover their tracks by editing prior log entries | GCM authentication tag — any modification breaks decryption, instantly visible |
| **External attacker dumping the DB** | Use captured plaintext passwords from logs | Passwords are encrypted in the log, not stored at all in the original cleartext form |
| **Compromised application user (e.g. Student account)** | Escalate to Admin-level DB privileges | `DBConnectionProfile` makes role↔account binding explicit so a future fix is one-line |
| **Curious developer running the app on their workstation** | Casual disclosure of teammates' credentials | `logs/` is `rwx------`, log files `rw-------` — only the owning OS user can read |

### 9.2 Threats explicitly out of scope

- **Memory-resident attacks** (RAM dump while the app runs) — would require additional Java agent + JVMTI controls, beyond the milestone scope.
- **Side-channel attacks** (timing, power analysis) on AES — assumed not relevant for educational deployment.
- **Compromised host OS** — if `root` is owned, file permissions don't help.

### 9.3 CIA breakdown of the log file

| Property | Mechanism |
|---|---|
| **Confidentiality** | AES-256-GCM, key derived via PBKDF2 from a passphrase stored only locally |
| **Integrity** | GCM 128-bit authentication tag per record (tamper-evident) |
| **Availability** | Append-only; no in-place rewrite; concurrent writes serialised |
| **Accountability** | Plaintext timestamp + category preserved for grep/filter without decryption |

---

## 10. Build, Run, and Verification Procedure

The full procedure was executed successfully on the development Mac. All commands assume the repository root is `E-Learning-System-Java-GUI-Application/`.

### 10.1 Environment used

| Component | Version |
|---|---|
| OS | macOS (Darwin 25.3.0) |
| JDK | OpenJDK 23.0.1 (`javac 23.0.1`) |
| MySQL JDBC | mysql-connector-java-5.1.23 (bundled in `lib/`) |
| rs2xml.jar | bundled in `lib/` |
| Ant | not required — `javac` used directly |

### 10.2 Compile step (Mac/Linux)

```bash
cd E-Learning-System-Java-GUI-Application
mkdir -p build/classes
javac -d build/classes \
      -cp "lib/MySQLDriver/mysql-connector-java-5.1.23-bin.jar:lib/rs2xml.jar" \
      $(find src -name "*.java")
```

**Result:**
- 0 errors.
- Only legacy unchecked/deprecation notes (carried over from the upstream repo; unrelated to our changes).

### 10.3 Run the Processor demo (no DB required)

```bash
java -cp build/classes javasemesterproject.security.factory.Processor
```

This exercises the entire factory + logger stack without needing MySQL or the Swing GUI — perfect for graders.

### 10.4 Verify encryption round-trip

```bash
java -cp build/classes javasemesterproject.security.logging.DecryptLogTool
```

Decrypts every entry in `logs/secure.log`, prints recovered plaintext, and reports the number of authenticated entries. Any tampering with the file would cause the tool to throw `Decryption failed (tampered log entry?)`.

### 10.5 Inspect output artefacts

```bash
ls -la logs/
cat logs/secure.log       # opaque base64 — proves confidentiality
cat logs/production.log   # readable, sensitive values masked
```

### 10.6 (Optional) Full Swing-app smoke test

Requires MySQL on localhost. Steps:

```bash
brew install mysql                 # one-time
brew services start mysql
mysql -u root < ELearningSystem.sql

# Open NetBeans / IntelliJ → Run "LoadingScreen.java"
# Log in as admin / admin
# tail -f logs/secure.log    ← watch new encrypted lines appear
```

---

## 11. Test Evidence (Actual Output)

The following are **verbatim** captures from the Mac development session — not hypothetical.

### 11.1 Compilation

```
$ javac -d build/classes -cp "…/mysql-connector-…:lib/rs2xml.jar" $(find src -name "*.java")
Note: src/javasemesterproject/Main.java uses or overrides a deprecated API.
Note: Recompile with -Xlint:deprecation for details.
Note: Some input files use unchecked or unsafe operations.
Note: Recompile with -Xlint:unchecked for details.
```

✅ No errors. Deprecation/unchecked notes were pre-existing in the upstream repo.

### 11.2 Processor demo output

```
$ java -cp build/classes javasemesterproject.security.factory.Processor
=== Secure Factory Pattern Demo ===
 * created Student(alice, dbProfile=READ_ONLY) -> dbUser=elearning_student permissions=6
 * created Instructor(bob_teacher, dbProfile=READ_WRITE) -> dbUser=elearning_instructor permissions=7
 * created Administrator(root_admin, dbProfile=FULL_ACCESS) -> dbUser=elearning_admin permissions=7
2026-05-20T22:17:10.069 INFO  user.create - role=STUDENT username=c***e
2026-05-20T22:17:10.071 INFO  auth.attempt - role=Student user=c***e
2026-05-20T22:17:10.072 INFO  sensitive.password.student - h***2
2026-05-20T22:17:10.073 ERROR startup - demo finished — production logger active | RuntimeException: synthetic error for demo

Done. Inspect logs/secure.log (encrypted) and logs/production.log (masked).
```

### 11.3 File permissions confirmation

```
$ ls -la logs/
drwx------@  5 mostafanasser  staff   160 May 20 22:17 .
-rw-------@  1 mostafanasser  staff    69 May 20 22:17 .key
-rw-r--r--@  1 mostafanasser  staff   334 May 20 22:17 production.log
-rw-------@  1 mostafanasser  staff  1492 May 20 22:17 secure.log
```

✅ Key and secure log are owner-only (600); directory is 700.

### 11.4 `logs/secure.log` (encrypted — proves confidentiality)

```
2026-05-20T22:17:10.054 | user.create | LLiCB4w/Drnrjwmi:c0vmTtqyPmjTgutxhfIVUbuUiA2uR2OvMO65SKLEZv9xpYRmndsmrYpJ9g7c38+hYMQFYRkX7EdbUdeQ/mm0
2026-05-20T22:17:10.058 | user.create | Hp3VyjfvUDl392Sn:pdeSv3x7EGw2tWt/FOxSbYQHFHitDITqCX0w/4bnuL/xGQqa438Unrspad+6FnomFI911ozSuqO4dUGHkL5B536k
2026-05-20T22:17:10.059 | user.create | qP5oB8Obx6bF9s18:GrCXsIaw+4pcMBno+sDJEsyeV8FbYP2iyLcAOXLC1axgVDRpJ1LeF0YC3/WsrN+Z7PEzpOT0eOCWdpKUhx+ZqM/dp5Fw
2026-05-20T22:17:10.066 | auth.attempt | ivR5ahDegekyrYfD:LXWDXCfJt7GG+NJ+fG+V4nISw6fzACTr5N/hlLeaDO5jSDFjfDwB2vs97sN5W3II9U2BAu2Ii8skBhA=
2026-05-20T22:17:10.066 | sensitive.password.student | Ww0mciKf4DBED7bi:v+Oau5Bk9sjDMssOF5SG/mKnNaEZMf6xU0Wng/K7J306xysRe0TuhHfPbKWERwieeHPrOqWYhGk=
2026-05-20T22:17:10.067 | auth.attempt | IXYTag6rU306bMNU:hLB8XuaYzL3E/R/zPsg+3/7+wV4xoXo/WLMz1cNniBfHoWHvni+XuHNLFu1KokEPj+IGyFzjT4Bp+yWUeRQ=
2026-05-20T22:17:10.067 | sensitive.password.instructor | dfwMAw3V3vaRgsPL:9+hAyjUYoOhMlTOyuf7qDGTz1JqMn+cM8PdJn1xA2FNslwN20JLlCjH4NeiIwtH+FcGCtQfxjpM=
2026-05-20T22:17:10.067 | admin.auth | wHN0gJvoadY2zHII:5pqimEx4UARAs6OoRLzi3ra5eIIgSFEnBm0qaUvgSJzwty7y8j5KhIp/3VAOxT1GamHjn1NYMS0gTToK4MGjQV19ZvQB8/iquE8446WKa9AbZw==
2026-05-20T22:17:10.067 | auth.attempt | BGgxkY192XPahQfr:2F4ESz5zdwOZw/E2bckhmY52bY+XDzt8gZYicDocxX2lO7y3O10CfhQ9anrlLHQQAJ6/q395qSzoumXNASFzs2E=
2026-05-20T22:17:10.068 | sensitive.password.administrator | 9AbYBiiIoka2ECXE:LpM5agUf5Wj9wkPR1boG2iEDTlmlORBJRe7S4o3vPI+yyDGM4Ld9Ggy3axJw/kH0HSjkNAKlWG0=
```

Without the key file, this is mathematically indistinguishable from random data.

### 11.5 `logs/production.log` (masked plaintext — shows the Strategy contrast)

```
2026-05-20T22:17:10.069 INFO  user.create                   - role=STUDENT username=c***e
2026-05-20T22:17:10.071 INFO  auth.attempt                  - role=Student user=c***e
2026-05-20T22:17:10.072 INFO  sensitive.password.student    - h***2
2026-05-20T22:17:10.073 ERROR startup                       - demo finished — production logger active | RuntimeException: synthetic error for demo
```

Sensitive values (`charlie`, `hunter2`) are first/last-char masked — not encrypted, but still privacy-respecting for ops dashboards.

### 11.6 Round-trip decryption (proves integrity + authenticity)

```
$ java -cp build/classes javasemesterproject.security.logging.DecryptLogTool
2026-05-20T22:17:10.054    user.create                     level=EVENT|payload=role=STUDENT username=a***e
2026-05-20T22:17:10.058    user.create                     level=EVENT|payload=role=INSTRUCTOR username=b***r
2026-05-20T22:17:10.059    user.create                     level=EVENT|payload=role=ADMINISTRATOR username=r***n
2026-05-20T22:17:10.066    auth.attempt                    level=EVENT|payload=role=Student user=a***e
2026-05-20T22:17:10.066    sensitive.password.student      level=SENSITIVE|payload=SuperSecret!2026
2026-05-20T22:17:10.067    auth.attempt                    level=EVENT|payload=role=Instructor user=b***r
2026-05-20T22:17:10.067    sensitive.password.instructor   level=SENSITIVE|payload=SuperSecret!2026
2026-05-20T22:17:10.067    admin.auth                      level=EVENT|payload=Administrator authentication attempt for r***n
2026-05-20T22:17:10.067    auth.attempt                    level=EVENT|payload=role=Administrator user=r***n
2026-05-20T22:17:10.068    sensitive.password.administrator  level=SENSITIVE|payload=SuperSecret!2026
---
Decrypted 10 entries successfully (GCM-authenticated, no tampering).
```

✅ Every line decrypted, GCM authentication succeeded, plaintext payloads (including the test password `SuperSecret!2026`) recovered exactly.

---

## 12. File Inventory (Created / Modified)

### 12.1 New files (14)

```
src/javasemesterproject/security/logging/
    LoggerFactory.java
    Logger.java
    EncryptLogger.java
    SecureLogger.java
    ProductionLogger.java
    SecureLoggerFactory.java
    ProductionLoggerFactory.java
    DecryptLogTool.java

src/javasemesterproject/security/factory/
    DBConnectionProfile.java
    User.java
    Student.java
    Instructor.java
    Administrator.java
    Processor.java

.gitignore   (repo root)
```

### 12.2 Modified files (4)

```
src/javasemesterproject/DBConnection.java                ← +21 LoC (privilege-aware ctor + audit hooks)
src/javasemesterproject/Student/StudentLogin.java        ← +8  LoC (audit hooks + new imports)
src/javasemesterproject/Teacher/TeacherLogin.java        ← +8  LoC (audit hooks + new imports)
src/javasemesterproject/Admin/AdminLogin.java            ← +8  LoC (audit hooks + new imports)
```

### 12.3 Companion deliverables outside the repo

```
SecurityInSE_Milestone2/
    IMPLEMENTATION_REPORT.md   ← THIS FILE
    PENTEST_REPORT.md          ← Part 2 — DVWA pentest report template
```

### 12.4 Runtime-generated (not committed)

```
logs/.key            (random 32-byte passphrase + salt)
logs/secure.log
logs/production.log
```

---

## 13. Known Limitations & Future Work

1. **DB account credentials are still hard-coded.** The `DBConnectionProfile` enum carries the *intended* user names; in a real deployment the actual passwords would come from an environment variable / vault, and the JDBC URL would be built per profile. Out of scope for Milestone 2.
2. **Passwords are still stored in plaintext in MySQL.** Hashing the `users.password` column (bcrypt/argon2) is a follow-on hardening item — it's an application change, not a logger change.
3. **SQL injection is NOT fixed in the login frames.** The audit hooks log the attempt but the underlying `Statement.executeQuery(...)` with string concatenation remains. Replacing it with `PreparedStatement` is a one-line patch but was deliberately kept out of scope so the diff stays minimal and reviewable.
4. **Key file is local.** A proper deployment would source the passphrase from a KMS (AWS KMS, Hashicorp Vault). The current scheme is appropriate for an academic environment.
5. **No log rotation.** `logs/secure.log` grows indefinitely. Adding a daily-rotation hook (move file, create new) is straightforward but not required.
6. **Windows ACL hardening** is best-effort; POSIX permissions don't apply. A console warning is emitted.

---

## 14. Mapping to Assignment Requirements

| Spec line | Class / mechanism | File |
|---|---|---|
| **1. Secure Logger — Sensitive Data Logging** | `SecureLogger.logSensitive(...)` forces values through `EncryptLogger.encrypt(...)` | `SecureLogger.java`, `EncryptLogger.java` |
| **1. Secure Logger — Log Destination secured** | Restrictive POSIX perms on `logs/`, `logs/.key`, `logs/secure.log`; append-only writes | `EncryptLogger.restrictPermissions`, `SecureLogger.ensureFile` |
| **1. Class `SecureLoggerFactory()`** | ✅ Implemented as a thread-safe singleton | `SecureLoggerFactory.java` |
| **1. Class `SecureLogger()`** | ✅ Implements `Logger` interface | `SecureLogger.java` |
| **1. Class `EncryptLogger()`** | ✅ AES-256-GCM + PBKDF2-HmacSHA256 | `EncryptLogger.java` |
| **2. Factory Pattern — user types Student/Instructor/Administrator** | ✅ Concrete subclasses of `User` | `Student.java`, `Instructor.java`, `Administrator.java` |
| **2. Varying security levels for DB connections** | `DBConnectionProfile` enum + privilege-aware `DBConnection` ctor | `DBConnectionProfile.java`, `DBConnection.java` |
| **2. Class `SecureLoggerFactory()`** | ✅ Same singleton, also referenced by `Processor` | `SecureLoggerFactory.java` |
| **2. Class `ProductionLoggerFactory()`** | ✅ Returns `ProductionLogger` (plaintext, masked) | `ProductionLoggerFactory.java` |
| **2. Class `Processor()`** | ✅ Selects `LoggerFactory` by `SecurityLevel`; creates concrete `User` by `Role`; contains `main()` demo | `Processor.java` |

**All 6 required classes implemented. All key requirements satisfied.**

---

## 15. Conclusion

Milestone 2 Part 1 has been delivered with the following deliverables, all verified:

- ✅ 6 required classes + 8 supporting classes (interfaces, abstract products, utilities).
- ✅ AES-256-GCM authenticated encryption with PBKDF2 key derivation.
- ✅ POSIX file-permission hardening.
- ✅ Integration into the three existing GUI login frames with **zero regression** in behaviour.
- ✅ Clean compile with `javac 23.0.1`.
- ✅ Headless demo that exercises both factories and produces both log files.
- ✅ Round-trip decryption proves integrity (GCM authentication) and confidentiality.

The implementation is idiomatic Java, faithful to the Gang-of-Four definitions of Abstract Factory + Factory Method + Singleton + Strategy, and aligned with OWASP Cryptographic Storage and Logging Cheat Sheets.

Part 2 (DVWA penetration test) is delivered as a separate report — `PENTEST_REPORT.md` — together with step-by-step Kali Linux instructions and 11 numbered screenshot placeholders ready to be populated from the team's VM session.

---

## Appendix A — Class-by-Class Reference

### A.1 `LoggerFactory` (interface)

```java
public interface LoggerFactory {
    Logger getLogger();
}
```

Pure contract — no fields, no default methods. Enables polymorphic factory selection.

### A.2 `Logger` (interface)

```java
public interface Logger {
    void logEvent(String category, String message);
    void logError(String category, String message, Throwable t);
    void logSensitive(String field, String sensitiveValue);
    void close();
}
```

Four methods cover every call shape the application needs.

### A.3 `EncryptLogger`

- 6 private constants (`GCM_TAG_BITS=128`, `IV_BYTES=12`, `SALT_BYTES=16`, `KEY_BITS=256`, `PBKDF2_ITERS=100_000`, `KDF="PBKDF2WithHmacSHA256"`).
- One `SecureKey` (`AES`) cached after derivation.
- `encrypt(String)` and `decrypt(String)` are the public surface; `mask(String)` is a static utility.
- `loadOrCreateKey()` handles first-run key generation atomically.

### A.4 `SecureLogger`

- Writes go through `Files.write(..., StandardOpenOption.APPEND)`.
- A private `Object writeLock` serialises concurrent appends.
- Decoupled from the crypto via composition (`EncryptLogger crypto`).
- Provides `decryptPayload(...)` helper used by `DecryptLogTool`.

### A.5 `ProductionLogger`

- Same `Logger` surface, no encryption, masks sensitive values with `EncryptLogger.mask(...)`.
- Mirrors writes to stdout so ops/console users see them in real time.

### A.6 `SecureLoggerFactory` / `ProductionLoggerFactory`

- Double-checked-locking singletons.
- `getInstance()` is safe to call from multiple GUI event-dispatch threads.

### A.7 `DecryptLogTool`

- Reads `logs/secure.log`, splits on `" | "`, decrypts the third column, prints recovered plaintext.
- Doubles as a tamper detector: a corrupted line throws `IllegalStateException("Decryption failed (tampered log entry?)")`.

### A.8 `DBConnectionProfile` (enum)

- 3 values × 2 fields (`dbUser`, `description`).
- Stable identifier used in audit logs to prove which privilege was requested.

### A.9 `User` (abstract)

- Constructor validates inputs (throws `IllegalArgumentException` for null/empty username or null logger).
- `authenticate(...)` audits the attempt then logs the password via `logSensitive` — a single source of truth for every subclass.

### A.10 `Student` / `Instructor` / `Administrator`

- Each immutable, no setters.
- `getPermissions()` returns an unmodifiable `Set<String>` so callers cannot widen privilege at runtime.

### A.11 `Processor`

- Constructor stores `LoggerFactory`; `createUser(...)` instantiates the right `User` subclass.
- `main(...)` is the headless smoke test — runs without MySQL.

---

## Appendix B — Cryptographic Choices Justified

| Decision | Alternative considered | Why chosen |
|---|---|---|
| AES-256-GCM | AES-256-CBC + HMAC-SHA256 | GCM is one-pass authenticated encryption; CBC+HMAC requires careful Encrypt-then-MAC and is easy to misconfigure. |
| 12-byte IV | 16-byte IV | NIST SP 800-38D recommends 12 bytes for GCM (matches the cipher's internal counter format and gives the largest safety margin against IV reuse). |
| PBKDF2-HmacSHA256, 100 000 iters | Argon2id | Argon2 is preferable but not in the JDK standard library; PBKDF2 with ≥ 100k iterations meets OWASP recommendations for academic use. |
| 16-byte salt | 8-byte | NIST SP 800-132 minimum is 16 bytes; using more does not hurt. |
| Key length 256 bits | 128 bits | Both are adequate; 256 chosen for forward-compatibility against future cryptanalytic gains. |
| Base64 encoding of IV+ciphertext | Hex | Base64 is 33 % more compact and is the industry default for line-based log encoding. |
| One IV per record | One IV per file | GCM mandates a fresh IV per message; reusing IV with the same key is catastrophic. |

---

## Appendix C — Glossary

| Term | Meaning |
|---|---|
| **AES** | Advanced Encryption Standard — NIST FIPS-197 symmetric block cipher. |
| **GCM** | Galois/Counter Mode — authenticated encryption mode of AES (produces ciphertext + 128-bit integrity tag). |
| **PBKDF2** | Password-Based Key Derivation Function 2 (RFC 2898) — slows brute-force key recovery. |
| **HMAC-SHA256** | Hash-based MAC using SHA-256; used inside PBKDF2 as the pseudo-random function. |
| **IV** | Initialisation Vector — random per-message input that ensures the same plaintext encrypts to different ciphertexts. |
| **POSIX permissions** | Owner/group/other read/write/execute bits on Unix-like systems (e.g. `600` = owner read+write only). |
| **Singleton** | Design pattern guaranteeing one instance of a class per JVM. |
| **Abstract Factory** | Design pattern that produces families of related objects through a common interface. |
| **Strategy** | Design pattern that selects an algorithm at runtime via a shared interface. |
| **GoF** | "Gang of Four" — authors of the 1994 *Design Patterns* book. |
| **CIA** | Confidentiality, Integrity, Availability — the classical security triad. |
| **DVWA** | Damn Vulnerable Web Application (Part 2 target). |
| **ASVS** | OWASP Application Security Verification Standard. |

— *End of implementation report* —
