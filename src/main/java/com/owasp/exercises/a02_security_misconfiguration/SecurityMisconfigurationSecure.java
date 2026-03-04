package com.owasp.exercises.a02_security_misconfiguration;

/**
 * A02:2025 - Security Misconfiguration (CORRECTO).
 * Configuración desde variables de entorno o sistema de configuración seguro.
 * Sin credenciales en código; debug según entorno.
 */
public final class SecurityMisconfigurationSecure {

    private final String dbPassword;
    private final String apiKey;
    private final boolean debug;

    public SecurityMisconfigurationSecure() {
        this.dbPassword = System.getenv("DB_PASSWORD");
        this.apiKey = System.getenv("API_KEY");
        this.debug = "true".equalsIgnoreCase(System.getenv("DEBUG"));
    }

    public SecurityMisconfigurationSecure(String dbPassword, String apiKey, boolean debug) {
        this.dbPassword = dbPassword;
        this.apiKey = apiKey;
        this.debug = debug;
    }

    public String getDbConnectionString(String host) {
        if (dbPassword == null || dbPassword.isBlank()) {
            throw new IllegalStateException("DB_PASSWORD no configurado");
        }
        return "jdbc:mysql://" + host + "?password=" + dbPassword;
    }

    public String getApiKey() {
        return apiKey;
    }

    public boolean isDebugEnabled() {
        return debug;
    }
}
