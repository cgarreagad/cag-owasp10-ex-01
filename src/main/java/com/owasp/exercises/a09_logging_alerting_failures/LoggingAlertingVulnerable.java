package com.owasp.exercises.a09_logging_alerting_failures;

/**
 * A09:2025 - Security Logging and Alerting Failures (VULNERABLE).
 * Ejemplo: no registrar fallos de autenticación, registrar datos sensibles, sin alertas.
 * Ver: https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Alerting_Failures/
 */
public final class LoggingAlertingVulnerable {

    /**
     * VULNERABLE: no se registra el intento fallido de login (no hay auditoría).
     */
    public boolean login(String user, String password) {
        boolean ok = "admin".equals(user) && "secret123".equals(password);
        return ok;
    }

    /**
     * VULNERABLE: se registra la contraseña en texto plano en el log.
     */
    public void logLoginAttempt(String user, String password, boolean success) {
        System.out.println("Login attempt: user=" + user + " password=" + password + " success=" + success);
    }

    /**
     * VULNERABLE: excepción tragada sin log ni alerta.
     */
    public void processRequest(String input) {
        try {
            doProcess(input);
        } catch (Exception e) {
            // Nada: no se registra ni se alerta
        }
    }

    private void doProcess(String input) {
        if (input == null) throw new IllegalArgumentException("input null");
    }
}
