package com.owasp.exercises.a03_software_supply_chain;

import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;

/**
 * A03:2025 - Software Supply Chain Failures (VULNERABLE).
 * Ejemplo: cargar y ejecutar código desde una URL no verificada (dependencia no confiable).
 * Ver: https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/
 */
public final class SupplyChainVulnerable {

    /**
     * VULNERABLE: descarga y usa contenido de una URL sin verificar integridad,
     * procedencia ni lista blanca de orígenes.
     */
    public String loadScriptFromUrl(String urlString) throws Exception {
        URL url = new URL(urlString);
        try (InputStream in = url.openStream()) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
