import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Scanner;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class PasswordAuthentication {
    private static final HashMap<String, User> users = new HashMap<>();
    private static final Scanner scanner = new Scanner(System.in);
    private static final SecureRandom random = new SecureRandom();

    // PBKDF2-HMAC-SHA-256 parameters. Increase iterations as hardware permits.
    private static final int ITERATIONS = 210_000;
    private static final int KEY_LENGTH = 256;
    private static final int SALT_LENGTH = 16;
    private static final long LOCK_DURATION_MS = 30_000;

    private static class PasswordRecord {
        final byte[] salt;
        final byte[] hash;

        PasswordRecord(byte[] salt, byte[] hash) {
            this.salt = salt;
            this.hash = hash;
        }
    }

    private static class User {
        final String username;
        PasswordRecord passwordRecord;
        final String securityQuestion;
        final PasswordRecord securityAnswerRecord;
        int failedAttempts;
        long lockedUntil;

        User(String username, PasswordRecord passwordRecord,
             String securityQuestion, PasswordRecord securityAnswerRecord) {
            this.username = username;
            this.passwordRecord = passwordRecord;
            this.securityQuestion = securityQuestion;
            this.securityAnswerRecord = securityAnswerRecord;
            this.failedAttempts = 0;
            this.lockedUntil = 0;
        }
    }

    private static PasswordRecord createPasswordRecord(String value) {
        byte[] salt = new byte[SALT_LENGTH];
        random.nextBytes(salt);
        return new PasswordRecord(salt, deriveHash(value, salt));
    }

    private static byte[] deriveHash(String value, byte[] salt) {
        PBEKeySpec spec = new PBEKeySpec(value.toCharArray(), salt, ITERATIONS, KEY_LENGTH);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            return factory.generateSecret(spec).getEncoded();
        } catch (Exception e) {
            throw new IllegalStateException("Password hashing is unavailable.", e);
        } finally {
            spec.clearPassword();
        }
    }

    private static boolean verify(String candidate, PasswordRecord record) {
        byte[] candidateHash = deriveHash(candidate, record.salt);
        return MessageDigest.isEqual(candidateHash, record.hash);
    }

    private static void register() {
        System.out.print("Enter username: ");
        String username = scanner.nextLine().trim();

        if (username.isEmpty() || users.containsKey(username)) {
            System.out.println("Username is invalid or already exists.");
            return;
        }

        System.out.print("Enter password: ");
        String password = scanner.nextLine();
        if (password.isEmpty()) {
            System.out.println("Password cannot be empty.");
            return;
        }

        System.out.print("Enter security question: ");
        String question = scanner.nextLine();
        System.out.print("Enter security answer: ");
        String answer = scanner.nextLine();

        User user = new User(username, createPasswordRecord(password), question,
                createPasswordRecord(normalizeAnswer(answer)));
        users.put(username, user);
        System.out.println("Account created successfully!");
    }

    private static String normalizeAnswer(String answer) {
        return answer.trim().toLowerCase(java.util.Locale.ROOT);
    }

    private static void login() {
        System.out.print("Enter username: ");
        String username = scanner.nextLine();
        System.out.print("Enter password: ");
        String password = scanner.nextLine();

        User user = users.get(username);
        long now = System.currentTimeMillis();

        // Use the same outward-facing failure message for unknown users and wrong passwords.
        if (user == null) {
            System.out.println("Invalid username or password.");
            return;
        }

        if (now < user.lockedUntil) {
            long seconds = Math.max(1, (user.lockedUntil - now + 999) / 1000);
            System.out.println("Account temporarily locked. Try again in " + seconds + " seconds.");
            return;
        }

        if (verify(password, user.passwordRecord)) {
            user.failedAttempts = 0;
            user.lockedUntil = 0;
            System.out.println("Login successful!");
        } else {
            user.failedAttempts++;
            System.out.println("Invalid username or password.");
            if (user.failedAttempts >= 3) {
                user.lockedUntil = System.currentTimeMillis() + LOCK_DURATION_MS;
                user.failedAttempts = 0;
                System.out.println("Account temporarily locked for 30 seconds.");
            }
        }
    }

    private static void resetPassword() {
        System.out.print("Enter username: ");
        String username = scanner.nextLine();
        User user = users.get(username);

        if (user == null) {
            System.out.println("Unable to verify account or security answer.");
            return;
        }

        System.out.println("Security Question: " + user.securityQuestion);
        System.out.print("Enter answer: ");
        String answer = scanner.nextLine();

        if (!verify(normalizeAnswer(answer), user.securityAnswerRecord)) {
            System.out.println("Unable to verify account or security answer.");
            return;
        }

        System.out.print("Enter new password: ");
        String newPassword = scanner.nextLine();
        if (newPassword.isEmpty()) {
            System.out.println("Password cannot be empty.");
            return;
        }

        user.passwordRecord = createPasswordRecord(newPassword);
        user.failedAttempts = 0;
        user.lockedUntil = 0;
        System.out.println("Password reset successfully!");
    }

    public static void main(String[] args) {
        while (true) {
            System.out.println("\n===== Password Authentication System =====");
            System.out.println("1. Register");
            System.out.println("2. Login");
            System.out.println("3. Reset Password");
            System.out.println("4. Exit");
            System.out.print("Choose an option: ");

            switch (scanner.nextLine()) {
                case "1": register(); break;
                case "2": login(); break;
                case "3": resetPassword(); break;
                case "4":
                    System.out.println("Goodbye!");
                    return;
                default:
                    System.out.println("Invalid option.");
            }
        }
    }
}
