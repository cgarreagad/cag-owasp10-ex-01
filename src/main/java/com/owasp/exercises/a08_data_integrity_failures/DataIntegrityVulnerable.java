package com.owasp.exercises.a08_data_integrity_failures;

import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.util.Base64;

/**
 * A08:2025 - Software or Data Integrity Failures (VULNERABLE).
 * Ejemplo: deserialización de datos no confiables sin verificar firma/integridad.
 * Ver: https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/
 */
public final class DataIntegrityVulnerable {

    /**
     * VULNERABLE: deserializar objeto Java desde entrada sin verificar procedencia ni firma.
     * Puede permitir ejecución de código (gadget chains).
     */
    public Object deserializeVulnerable(String base64Input) throws Exception {
        byte[] data = Base64.getDecoder().decode(base64Input);
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    /**
     * VULNERABLE: confiar en un JSON/XML de terceros sin validar firma.
     */
    public String processUpdateFromExternal(String jsonPayload) {
        return jsonPayload;  // Se usa sin verificar integridad
    }
}
