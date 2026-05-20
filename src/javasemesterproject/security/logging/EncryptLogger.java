package javasemesterproject.security.logging;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.EnumSet;
import java.util.Set;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * AES-256-GCM encryption helper used by {@link SecureLogger}.
 *
 * Design notes:
 *  - Key is derived from a passphrase via PBKDF2-HmacSHA256 (100k iterations,
 *    16-byte salt) so we never store a raw symmetric key on disk.
 *  - Salt + passphrase are persisted in {@code logs/.key}; file is created on
 *    first run with permissions rw-------  (POSIX). On Windows, where POSIX
 *    perms aren't supported, the file is created and a console warning is
 *    emitted so the operator can apply ACLs manually.
 *  - Each ciphertext gets a fresh 12-byte IV. Output format per encrypt() call:
 *        base64(iv) + ":" + base64(ciphertext||tag)
 *    so the decrypt() side can split and recover both pieces deterministically.
 *  - GCM provides authenticated encryption: any tampering of the log line
 *    will fail decryption, which makes the audit log tamper-evident.
 */
public final class EncryptLogger {

    private static final int GCM_TAG_BITS    = 128;
    private static final int IV_BYTES        = 12;
    private static final int SALT_BYTES      = 16;
    private static final int KEY_BITS        = 256;
    private static final int PBKDF2_ITERS    = 100_000;
    private static final String CIPHER       = "AES/GCM/NoPadding";
    private static final String KDF          = "PBKDF2WithHmacSHA256";
    private static final String KEY_FILE     = "logs/.key";
    private static final SecureRandom RNG    = new SecureRandom();

    private final SecretKey key;

    public EncryptLogger() {
        try {
            this.key = loadOrCreateKey();
        } catch (Exception e) {
            throw new IllegalStateException("Cannot initialise log encryption key", e);
        }
    }

    /** Encrypt the given UTF-8 plaintext. Returned form: base64(iv):base64(ct||tag). */
    public String encrypt(String plaintext) {
        try {
            byte[] iv = new byte[IV_BYTES];
            RNG.nextBytes(iv);

            Cipher c = Cipher.getInstance(CIPHER);
            c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
            byte[] ct = c.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

            Base64.Encoder b64 = Base64.getEncoder();
            return b64.encodeToString(iv) + ":" + b64.encodeToString(ct);
        } catch (Exception e) {
            throw new IllegalStateException("Encryption failed", e);
        }
    }

    /** Decrypt a value produced by {@link #encrypt(String)}. Throws on tampering. */
    public String decrypt(String token) {
        try {
            String[] parts = token.split(":", 2);
            if (parts.length != 2) {
                throw new IllegalArgumentException("Malformed encrypted token");
            }
            Base64.Decoder b64 = Base64.getDecoder();
            byte[] iv = b64.decode(parts[0]);
            byte[] ct = b64.decode(parts[1]);

            Cipher c = Cipher.getInstance(CIPHER);
            c.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
            byte[] pt = c.doFinal(ct);

            return new String(pt, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new IllegalStateException("Decryption failed (tampered log entry?)", e);
        }
    }

    /**
     * Mask a value so it can be safely written to the log header without
     * encryption — first and last chars only, e.g. "alice" -> "a***e".
     * For very short values (<3 chars) returns "***".
     */
    public static String mask(String value) {
        if (value == null || value.length() < 3) return "***";
        return value.charAt(0) + "***" + value.charAt(value.length() - 1);
    }

    // -----------------------------------------------------------------
    // Key material handling
    // -----------------------------------------------------------------

    private static SecretKey loadOrCreateKey() throws Exception {
        Path keyPath = Paths.get(KEY_FILE);
        Path parent  = keyPath.getParent();
        if (parent != null && !Files.exists(parent)) {
            Files.createDirectories(parent);
        }

        byte[] salt;
        char[] passphrase;

        if (Files.exists(keyPath)) {
            String content = new String(Files.readAllBytes(keyPath), StandardCharsets.UTF_8).trim();
            String[] parts = content.split(":", 2);
            if (parts.length != 2) {
                throw new IllegalStateException("Corrupt key file: " + KEY_FILE);
            }
            salt = Base64.getDecoder().decode(parts[0]);
            passphrase = parts[1].toCharArray();
        } else {
            salt = new byte[SALT_BYTES];
            RNG.nextBytes(salt);
            byte[] phraseBytes = new byte[32];
            RNG.nextBytes(phraseBytes);
            passphrase = Base64.getEncoder().encodeToString(phraseBytes).toCharArray();

            String payload = Base64.getEncoder().encodeToString(salt) + ":" + new String(passphrase);
            Files.write(keyPath, payload.getBytes(StandardCharsets.UTF_8));
            restrictPermissions(keyPath);
        }

        SecretKeyFactory f = SecretKeyFactory.getInstance(KDF);
        KeySpec spec = new PBEKeySpec(passphrase, salt, PBKDF2_ITERS, KEY_BITS);
        byte[] keyBytes = f.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }

    private static void restrictPermissions(Path p) {
        try {
            Set<PosixFilePermission> perms = EnumSet.of(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE);
            Files.setPosixFilePermissions(p, perms);
        } catch (UnsupportedOperationException | IOException e) {
            System.err.println("[EncryptLogger] WARNING: could not set POSIX perms on "
                    + p + " (likely Windows). Apply restrictive ACLs manually.");
        }
        try {
            // also ensure the logs dir itself is not world-readable where possible
            Path dir = p.getParent();
            if (dir != null) {
                Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("rwx------"));
            }
        } catch (UnsupportedOperationException | IOException ignored) {
            // best-effort
        }
    }
}
