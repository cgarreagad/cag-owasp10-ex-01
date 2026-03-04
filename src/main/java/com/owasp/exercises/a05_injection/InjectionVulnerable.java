package com.owasp.exercises.a05_injection;

import java.util.regex.Pattern;

/**
 * A05:2025 - Injection (VULNERABLE).
 * Ejemplo: concatenar entrada de usuario en consulta/comando sin sanitizar.
 * Ver: https://owasp.org/Top10/2025/A05_2025-Injection/
 */
public final class InjectionVulnerable {

    /**
     * VULNERABLE: construir "consulta" concatenando entrada de usuario.
     * Permite inyección (ej. "'; DROP TABLE users; --").
     */
    public String buildQueryVulnerable(String userName) {
        return "SELECT * FROM users WHERE name = '" + userName + "'";
    }

    /**
     * VULNERABLE: ejecución de comando con entrada sin validar.
     */
    public String buildCommandVulnerable(String filename) {
        return "cat " + filename;  // filename podría ser "../../etc/passwd" o "x; rm -rf /"
    }

    /**
     * VULNERABLE: regex con entrada de usuario puede causar ReDoS.
     */
    public boolean matchVulnerable(String userRegex, String input) {
        return Pattern.compile(userRegex).matcher(input).matches();
    }
}
