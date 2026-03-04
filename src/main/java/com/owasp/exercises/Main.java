package com.owasp.exercises;

import com.owasp.exercises.a01_broken_access_control.BrokenAccessControlSecure;
import com.owasp.exercises.a01_broken_access_control.BrokenAccessControlVulnerable;
import com.owasp.exercises.a02_security_misconfiguration.SecurityMisconfigurationSecure;
import com.owasp.exercises.a02_security_misconfiguration.SecurityMisconfigurationVulnerable;
import com.owasp.exercises.a03_software_supply_chain.SupplyChainSecure;
import com.owasp.exercises.a03_software_supply_chain.SupplyChainVulnerable;
import com.owasp.exercises.a04_cryptographic_failures.CryptographicFailuresSecure;
import com.owasp.exercises.a04_cryptographic_failures.CryptographicFailuresVulnerable;
import com.owasp.exercises.a05_injection.InjectionSecure;
import com.owasp.exercises.a05_injection.InjectionVulnerable;
import com.owasp.exercises.a06_insecure_design.InsecureDesignSecure;
import com.owasp.exercises.a06_insecure_design.InsecureDesignVulnerable;
import com.owasp.exercises.a07_authentication_failures.AuthenticationFailuresSecure;
import com.owasp.exercises.a07_authentication_failures.AuthenticationFailuresVulnerable;
import com.owasp.exercises.a08_data_integrity_failures.DataIntegritySecure;
import com.owasp.exercises.a09_logging_alerting_failures.LoggingAlertingSecure;
import com.owasp.exercises.a09_logging_alerting_failures.LoggingAlertingVulnerable;
import com.owasp.exercises.a09_logging_alerting_failures.SimpleLoginAudit;
import com.owasp.exercises.a10_mishandling_exceptional_conditions.MishandlingExceptionalSecure;
import com.owasp.exercises.a10_mishandling_exceptional_conditions.MishandlingExceptionalVulnerable;

import java.util.Base64;
import java.util.Collections;
import java.util.Scanner;
import java.util.Set;

/**
 * Menú principal para ejecutar ejemplos del OWASP Top 10:2025.
 * Cada opción muestra primero la ejecución vulnerable y luego la correcta.
 */
public class Main {

    public static void main(String[] args) {
        try (Scanner sc = new Scanner(System.in)) {
            int opcion;
            do {
                printMenu();
                opcion = readInt(sc, "Elija opción (0 = salir): ");
                if (opcion == 0) break;
                if (opcion >= 1 && opcion <= 10) {
                    runExample(opcion);
                } else {
                    System.out.println("Opción no válida. Use 1-10 o 0 para salir.");
                }
                System.out.println();
            } while (true);
            System.out.println("Hasta luego.");
        }
    }

    private static void printMenu() {
        System.out.println();
        System.out.println("=== OWASP Top 10:2025 - Ejemplos Java ===");
        System.out.println("  1. A01 - Broken Access Control");
        System.out.println("  2. A02 - Security Misconfiguration");
        System.out.println("  3. A03 - Software Supply Chain Failures");
        System.out.println("  4. A04 - Cryptographic Failures");
        System.out.println("  5. A05 - Injection");
        System.out.println("  6. A06 - Insecure Design");
        System.out.println("  7. A07 - Authentication Failures");
        System.out.println("  8. A08 - Software or Data Integrity Failures");
        System.out.println("  9. A09 - Security Logging and Alerting Failures");
        System.out.println(" 10. A10 - Mishandling of Exceptional Conditions");
        System.out.println("  0. Salir");
        System.out.println();
    }

    private static int readInt(Scanner sc, String prompt) {
        System.out.print(prompt);
        try {
            return Integer.parseInt(sc.nextLine().trim());
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    private static void runExample(int n) {
        if (n == 1) runA01();
        else if (n == 2) runA02();
        else if (n == 3) runA03();
        else if (n == 4) runA04();
        else if (n == 5) runA05();
        else if (n == 6) runA06();
        else if (n == 7) runA07();
        else if (n == 8) runA08();
        else if (n == 9) runA09();
        else if (n == 10) runA10();
    }

    private static void runA01() {
        System.out.println("\n--- A01:2025 Broken Access Control ---");
        BrokenAccessControlVulnerable vuln = new BrokenAccessControlVulnerable();
        BrokenAccessControlSecure secure = new BrokenAccessControlSecure();

        String docId = "doc-1";
        String bob = "user-bob";
        String alice = "user-alice";

        System.out.println("\n[VULNERABLE] user-bob pide doc-1 (pertenece a user-alice):");
        BrokenAccessControlVulnerable.Document docVuln = vuln.getDocument(docId, bob);
        System.out.println("  Resultado: " + (docVuln != null ? "ACCESO PERMITIDO -> " + docVuln.content() : "null"));
        System.out.println("  Riesgo: Bob puede leer documento de Alice.");

        System.out.println("\n[CORRECTO] user-bob pide doc-1 (pertenece a user-alice):");
        java.util.Optional<BrokenAccessControlSecure.Document> docSecure = secure.getDocument(docId, bob, false);
        System.out.println("  Resultado: " + (docSecure.isPresent() ? docSecure.get().content() : "Acceso denegado (Optional.empty)"));
        System.out.println("  Correcto: Solo el propietario o admin pueden ver el documento.");

        System.out.println("\n[CORRECTO] user-alice pide doc-1:");
        java.util.Optional<BrokenAccessControlSecure.Document> docAlice = secure.getDocument(docId, alice, false);
        if (docAlice.isPresent()) {
            System.out.println("  Resultado: " + docAlice.get().content());
        }
    }

    private static void runA02() {
        System.out.println("\n--- A02:2025 Security Misconfiguration ---");

        System.out.println("\n[VULNERABLE] Configuración en código:");
        SecurityMisconfigurationVulnerable vuln = new SecurityMisconfigurationVulnerable();
        System.out.println("  getApiKey() = " + vuln.getApiKey());
        System.out.println("  isDebugEnabled() = " + vuln.isDebugEnabled());
        System.out.println("  Riesgo: Secretos y debug expuestos en el binario.");

        System.out.println("\n[CORRECTO] Configuración desde entorno/inyección:");
        SecurityMisconfigurationSecure secure = new SecurityMisconfigurationSecure("***", "***", false);
        System.out.println("  getApiKey() = *** (desde variable/constructor)");
        System.out.println("  isDebugEnabled() = " + secure.isDebugEnabled());
        System.out.println("  Correcto: Sin credenciales en código.");
    }

    private static void runA03() {
        System.out.println("\n--- A03:2025 Software Supply Chain Failures ---");

        System.out.println("\n[VULNERABLE] Cargar desde URL arbitraria:");
        SupplyChainVulnerable vuln = new SupplyChainVulnerable();
        try {
            String content = vuln.loadScriptFromUrl("https://example.com");
            System.out.println("  Se aceptó cualquier URL. Contenido (primeros 80 chars): " + (content.length() > 80 ? content.substring(0, 80) + "..." : content));
        } catch (Exception e) {
            System.out.println("  Excepción: " + e.getMessage());
        }
        System.out.println("  Riesgo: Código o datos de orígenes no confiables.");

        System.out.println("\n[CORRECTO] Solo hosts en lista blanca y HTTPS:");
        Set<String> allowedHosts = Collections.singleton("example.com");
        SupplyChainSecure secure = new SupplyChainSecure(allowedHosts);
        try {
            secure.loadScriptFromUrl("http://example.com");
            System.out.println("  (no debería imprimirse)");
        } catch (Exception e) {
            System.out.println("  http://example.com -> " + e.getMessage());
        }
        try {
            secure.loadScriptFromUrl("https://evil.com");
            System.out.println("  (no debería imprimirse)");
        } catch (Exception e) {
            System.out.println("  https://evil.com -> " + e.getMessage());
        }
        System.out.println("  Correcto: Se rechazan esquema no HTTPS y hosts no permitidos.");
    }

    private static void runA04() {
        System.out.println("\n--- A04:2025 Cryptographic Failures ---");
        String password = "MiPassword123";

        System.out.println("\n[VULNERABLE] Hash con MD5:");
        CryptographicFailuresVulnerable vuln = new CryptographicFailuresVulnerable();
        try {
            String hashVuln = vuln.hashPassword(password);
            System.out.println("  hashPassword(\"" + password + "\") = " + hashVuln);
            System.out.println("  Riesgo: MD5 es débil (colisiones, rápido para fuerza bruta).");
        } catch (Exception e) {
            System.out.println("  Error: " + e.getMessage());
        }

        System.out.println("\n[CORRECTO] Hash con PBKDF2-HMAC-SHA256 (salt + iteraciones):");
        CryptographicFailuresSecure secure = new CryptographicFailuresSecure();
        try {
            String hashSecure = secure.hashPassword(password);
            System.out.println("  hashPassword(\"" + password + "\") = " + hashSecure.substring(0, Math.min(50, hashSecure.length())) + "...");
            boolean ok = secure.verifyPassword(password, hashSecure);
            System.out.println("  verifyPassword(correcta) = " + ok);
            System.out.println("  verifyPassword(incorrecta) = " + secure.verifyPassword("otra", hashSecure));
        } catch (Exception e) {
            System.out.println("  Error: " + e.getMessage());
        }
    }

    private static void runA05() {
        System.out.println("\n--- A05:2025 Injection ---");

        System.out.println("\n[VULNERABLE] Concatenar entrada en 'consulta':");
        InjectionVulnerable vuln = new InjectionVulnerable();
        String malicioso = "'; DROP TABLE users; --";
        System.out.println("  buildQueryVulnerable(\"" + malicioso + "\") = " + vuln.buildQueryVulnerable(malicioso));
        System.out.println("  Riesgo: Inyección SQL/comando.");

        System.out.println("\n[CORRECTO] Parámetro/validación:");
        InjectionSecure secure = new InjectionSecure();
        System.out.println("  buildQuerySecure(\"alice\") = " + secure.buildQuerySecure("alice"));
        try {
            secure.buildCommandSecure("../../etc/passwd");
        } catch (Exception e) {
            System.out.println("  buildCommandSecure(\"../../etc/passwd\") -> " + e.getMessage());
        }
        System.out.println("  buildCommandSecure(\"reporte.txt\") = cat reporte.txt");
    }

    private static void runA06() {
        System.out.println("\n--- A06:2025 Insecure Design ---");

        System.out.println("\n[VULNERABLE] Login sin límite de intentos:");
        InsecureDesignVulnerable vuln = new InsecureDesignVulnerable();
        for (int i = 0; i < 7; i++) vuln.login("admin", "wrong");
        System.out.println("  Se permiten intentos ilimitados (fuerza bruta).");

        System.out.println("\n[CORRECTO] Bloqueo tras 5 intentos fallidos:");
        InsecureDesignSecure secure = new InsecureDesignSecure();
        for (int i = 0; i < 6; i++) {
            boolean ok = secure.login("admin", "wrong");
            System.out.println("  Intento " + (i + 1) + ": login = " + ok);
        }
        System.out.println("  Tras 5 fallos, la cuenta se bloquea temporalmente.");
    }

    private static void runA07() {
        System.out.println("\n--- A07:2025 Authentication Failures ---");

        System.out.println("\n[VULNERABLE] Validación débil y credenciales por defecto:");
        AuthenticationFailuresVulnerable vuln = new AuthenticationFailuresVulnerable();
        System.out.println("  validatePassword(\"1\") = " + vuln.validatePassword("1"));
        System.out.println("  login(\"admin\", \"admin\") = " + vuln.login("admin", "admin"));
        System.out.println("  Riesgo: Contraseñas débiles y defaults aceptados.");

        System.out.println("\n[CORRECTO] Política fuerte y sin defaults:");
        AuthenticationFailuresSecure secure = new AuthenticationFailuresSecure();
        System.out.println("  validatePassword(\"1\") = " + secure.validatePassword("1"));
        System.out.println("  validatePassword(\"Abc123!@#xyz\") = " + secure.validatePassword("Abc123!@#xyz"));
        System.out.println("  login(\"admin\", \"admin\", ...) = " + secure.login("admin", "admin", null));
        long created = System.currentTimeMillis() - 20_000;
        System.out.println("  isSessionValid(..., hace 20s) = " + secure.isSessionValid("sid", created));
    }

    private static void runA08() {
        System.out.println("\n--- A08:2025 Software or Data Integrity Failures ---");

        System.out.println("\n[VULNERABLE] Deserialización sin verificar:");
        System.out.println("  Deserializar desde Base64 sin verificar firma/integridad.");
        System.out.println("  Riesgo: deserialización de objetos no confiables (gadget chains).");

        System.out.println("\n[CORRECTO] Payload firmado con HMAC:");
        DataIntegritySecure secure = new DataIntegritySecure();
        try {
            byte[] key = "secret-key-32-bytes!!!!!!!!!!".getBytes();
            byte[] payload = "datos confidenciales".getBytes();
            String payloadB64 = Base64.getEncoder().encodeToString(payload);
            String sigB64 = DataIntegritySecure.signPayload(payload, key);
            String result = secure.processSignedPayload(payloadB64, sigB64, key);
            System.out.println("  processSignedPayload(firma correcta) = \"" + result + "\"");
            secure.processSignedPayload(payloadB64, "firmaFalsa", key);
        } catch (Exception e) {
            System.out.println("  processSignedPayload(firma incorrecta) -> " + e.getMessage());
        }
    }

    private static void runA09() {
        System.out.println("\n--- A09:2025 Security Logging and Alerting Failures ---");

        System.out.println("\n[VULNERABLE] Login sin auditar; log con contraseña:");
        LoggingAlertingVulnerable vuln = new LoggingAlertingVulnerable();
        vuln.login("admin", "wrong");
        vuln.logLoginAttempt("admin", "secret123", false);
        System.out.println("  (En vulnerable se imprimiría la contraseña en el log.)");

        System.out.println("\n[CORRECTO] Auditoría sin datos sensibles:");
        LoggingAlertingSecure secure = new LoggingAlertingSecure();
        SimpleLoginAudit audit = new SimpleLoginAudit();
        secure.login("admin", "wrong", audit);
        secure.logLoginAttempt("admin", false);
        System.out.println("  Logs sin contraseña; usuario enmascarado; alerta tras múltiples fallos.");
    }

    private static void runA10() {
        System.out.println("\n--- A10:2025 Mishandling of Exceptional Conditions ---");

        System.out.println("\n[VULNERABLE] Devolver stack trace y revelar si usuario existe:");
        MishandlingExceptionalVulnerable vuln = new MishandlingExceptionalVulnerable();
        try {
            throw new RuntimeException("Error en /var/app/config/db.xml");
        } catch (Exception e) {
            String msg = vuln.handleError(e);
            int len = Math.min(80, msg.length());
            System.out.println("  handleError(e) = " + msg.substring(0, len) + (msg.length() > 80 ? "..." : ""));
        }
        System.out.println("  loginMessage(user no existe) = " + vuln.loginMessage(false, false));
        System.out.println("  loginMessage(contraseña mala) = " + vuln.loginMessage(true, false));
        System.out.println("  Riesgo: Info interna y enumeración de usuarios.");

        System.out.println("\n[CORRECTO] Mensaje genérico y mismo texto para usuario/contraseña:");
        MishandlingExceptionalSecure secure = new MishandlingExceptionalSecure();
        try {
            throw new RuntimeException("Error interno");
        } catch (Exception e) {
            System.out.println("  handleError(e) = " + secure.handleError(e));
        }
        System.out.println("  loginMessage(user no existe) = " + secure.loginMessage(false, false));
        System.out.println("  loginMessage(contraseña mala) = " + secure.loginMessage(true, false));
    }
}
