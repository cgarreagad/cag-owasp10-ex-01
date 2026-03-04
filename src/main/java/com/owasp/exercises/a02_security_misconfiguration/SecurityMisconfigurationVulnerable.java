package com.owasp.exercises.a02_security_misconfiguration;

/**
 * A02:2025 - Security Misconfiguration (VULNERABLE).
 * Ejemplo: credenciales o configuración sensible hardcodeada, debug activo en producción.
 * Ver: https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/
 */
public final class SecurityMisconfigurationVulnerable {

    // VULNERABLE: contraseña y datos sensibles en código
    private static final String DB_PASSWORD = "admin123";
    private static final String API_KEY = "sk-live-abc123xyz";
    private static final boolean DEBUG = true;  // No debería estar true en producción

    public String getDbConnectionString(String host) {
        return "jdbc:mysql://" + host + "?password=" + DB_PASSWORD;
    }

    public String getApiKey() {
        return API_KEY;
    }

    public boolean isDebugEnabled() {
        return DEBUG;
    }
}
