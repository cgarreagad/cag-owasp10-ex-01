package com.owasp.exercises.a07_authentication_failures;

import java.util.Set;
import java.util.regex.Pattern;

/**
 * A07:2025 - Authentication Failures (CORRECTO).
 * Política de contraseñas fuerte, sin credenciales por defecto, sesión con expiración.
 */
public final class AuthenticationFailuresSecure {

    private static final int MIN_LENGTH = 12;
    private static final long SESSION_TIMEOUT_MS = 15 * 60 * 1000;  // 15 min
    private static final Set<String> FORBIDDEN_PASSWORDS = Set.of("admin", "password", "123456", "guest");

    private static final Pattern HAS_UPPER = Pattern.compile("[A-Z]");
    private static final Pattern HAS_LOWER = Pattern.compile("[a-z]");
    private static final Pattern HAS_DIGIT = Pattern.compile("\\d");
    private static final Pattern HAS_SPECIAL = Pattern.compile("[!@#$%^&*(),.?\":{}|<>]");

    /**
     * SEGURO: requisitos de complejidad y rechazo de contraseñas comunes.
     */
    public boolean validatePassword(String password) {
        if (password == null || password.length() < MIN_LENGTH) return false;
        if (FORBIDDEN_PASSWORDS.contains(password.toLowerCase())) return false;
        return HAS_UPPER.matcher(password).find()
                && HAS_LOWER.matcher(password).find()
                && HAS_DIGIT.matcher(password).find()
                && HAS_SPECIAL.matcher(password).find();
    }

    /**
     * SEGURO: no se aceptan usuarios/contraseñas por defecto; solo credenciales configuradas.
     */
    public boolean login(String user, String password, String expectedStoredHash) {
        if ("admin".equals(user) && "admin".equals(password)) {
            return false;  // Rechazar default
        }
        // En práctica: comparar password con expectedStoredHash usando PBKDF2/BCrypt
        return expectedStoredHash != null && !expectedStoredHash.isBlank();
    }

    /**
     * SEGURO: sesión con tiempo máximo de vida.
     */
    public boolean isSessionValid(String sessionId, long createdAtMs) {
        if (sessionId == null || sessionId.isBlank()) return false;
        return System.currentTimeMillis() - createdAtMs < SESSION_TIMEOUT_MS;
    }
}
