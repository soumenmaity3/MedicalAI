package com.soumen.MedicalAI.utils;

import java.util.regex.Pattern;

/**
 * Password validation utility
 * Enforces strong password requirements
 */
public class PasswordValidator {

    // Password must be at least 8 characters, contain uppercase, lowercase, and
    // digit
    private static final Pattern PASSWORD_PATTERN = Pattern.compile(
            "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)[a-zA-Z\\d@$!%*?&]{8,}$");

    /**
     * Validate password strength
     * 
     * @param password The password to validate
     * @return true if password meets requirements
     */
    public static boolean isValid(String password) {
        if (password == null || password.isBlank()) {
            return false;
        }
        return PASSWORD_PATTERN.matcher(password).matches();
    }

    /**
     * Get password requirements message
     * 
     * @return String describing password requirements
     */
    public static String getRequirements() {
        return "Password must be at least 8 characters long and contain " +
                "at least one uppercase letter, one lowercase letter, and one number";
    }

    /**
     * Validate password and return error message if invalid
     * 
     * @param password The password to validate
     * @return null if valid, error message if invalid
     */
    public static String validate(String password) {
        if (password == null || password.isBlank()) {
            return "Password is required";
        }

        if (password.length() < 8) {
            return "Password must be at least 8 characters long";
        }

        if (!password.matches(".*[a-z].*")) {
            return "Password must contain at least one lowercase letter";
        }

        if (!password.matches(".*[A-Z].*")) {
            return "Password must contain at least one uppercase letter";
        }

        if (!password.matches(".*\\d.*")) {
            return "Password must contain at least one number";
        }

        return null; // Valid
    }
}
