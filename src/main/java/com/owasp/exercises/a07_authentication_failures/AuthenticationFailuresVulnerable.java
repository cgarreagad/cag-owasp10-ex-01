package com.owasp.exercises.a07_authentication_failures;

/**
 * A07:2025 - Authentication Failures (VULNERABLE).
 * Ejemplo: contraseñas débiles aceptadas, sesión sin timeout, credenciales por defecto.
 * Ver: https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/
 */
public final class AuthenticationFailuresVulnerable {

    /**
     * VULNERABLE: acepta cualquier contraseña sin requisitos mínimos.
     */
    public boolean validatePassword(String password) {
        return password != null && password.length() >= 1;
    }

    /**
     * VULNERABLE: credenciales por defecto permitidas en producción.
     */
    public boolean login(String user, String password) {
        return ("admin".equals(user) && "admin".equals(password))
                || ("guest".equals(user) && "guest".equals(password));
    }

    /**
     * VULNERABLE: sesión que nunca expira.
     */
    public boolean isSessionValid(String sessionId, long createdAt) {
        return sessionId != null && !sessionId.isBlank();
    }
}
