package com.owasp.exercises.a06_insecure_design;

/**
 * A06:2025 - Insecure Design (VULNERABLE).
 * Ejemplo: diseño que asume que el usuario no hará intentos masivos (sin rate limit),
 * o que no se necesita flujo de recuperación de cuenta.
 * Ver: https://owasp.org/Top10/2025/A06_2025-Insecure_Design/
 */
public final class InsecureDesignVulnerable {

    private int loginAttempts = 0;

    /**
     * VULNERABLE: sin límite de intentos ni bloqueo temporal; permite fuerza bruta.
     */
    public boolean login(String user, String password) {
        loginAttempts++;
        return "admin".equals(user) && "secret123".equals(password);
    }

    /**
     * VULNERABLE: recuperación de contraseña sin verificar identidad (solo email).
     */
    public void resetPassword(String email) {
        // Envía link de reset a email sin comprobar que el que pide es el dueño
        sendResetLink(email);
    }

    private void sendResetLink(String email) {
        // simulado
    }
}
