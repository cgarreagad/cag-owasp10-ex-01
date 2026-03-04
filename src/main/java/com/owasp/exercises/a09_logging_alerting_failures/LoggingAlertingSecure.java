package com.owasp.exercises.a09_logging_alerting_failures;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * A09:2025 - Security Logging and Alerting (CORRECTO).
 * Registrar eventos de seguridad sin datos sensibles; alertar en fallos críticos.
 */
public final class LoggingAlertingSecure {

    private static final Logger LOG = Logger.getLogger(LoggingAlertingSecure.class.getName());

    /**
     * SEGURO: registrar intento fallido sin contraseña; alertar si hay muchos fallos.
     */
    public boolean login(String user, String password, LoginAudit audit) {
        boolean ok = "admin".equals(user) && "secret123".equals(password);
        if (!ok) {
            audit.recordFailedAttempt(user);
            LOG.warning("Failed login attempt for user: " + maskUser(user));
            if (audit.getFailedAttempts(user) >= 5) {
                LOG.severe("ALERT: Multiple failed logins for user: " + maskUser(user));
            }
        }
        return ok;
    }

    /**
     * SEGURO: log sin datos sensibles (no contraseña, usuario enmascarado si procede).
     */
    public void logLoginAttempt(String user, boolean success) {
        if (success) {
            LOG.info("Successful login for user: " + maskUser(user));
        } else {
            LOG.warning("Failed login for user: " + maskUser(user));
        }
    }

    /**
     * SEGURO: excepción registrada con nivel y mensaje; no tragar.
     */
    public void processRequest(String input) {
        try {
            if (input == null) throw new IllegalArgumentException("input null");
        } catch (Exception e) {
            LOG.log(Level.SEVERE, "Error processing request", e);
            throw e;
        }
    }

    private static String maskUser(String user) {
        if (user == null || user.length() <= 2) return "***";
        return user.charAt(0) + "***" + user.charAt(user.length() - 1);
    }

    public interface LoginAudit {
        void recordFailedAttempt(String user);
        int getFailedAttempts(String user);
    }
}
