package com.owasp.exercises.a01_broken_access_control;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A01:2025 - Broken Access Control (VULNERABLE).
 * Ejemplo: acceso a recurso sin verificar que el usuario tiene permiso.
 * Ver: https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/
 */
public final class BrokenAccessControlVulnerable {

    private final Map<String, Document> documents = new ConcurrentHashMap<>();

    public BrokenAccessControlVulnerable() {
        documents.put("doc-1", new Document("doc-1", "user-alice", "Contenido confidencial de Alice"));
        documents.put("doc-2", new Document("doc-2", "user-bob", "Contenido confidencial de Bob"));
    }

    /**
     * VULNERABLE: devuelve el documento por ID sin comprobar si el usuario actual
     * tiene derecho a verlo. Cualquier usuario puede pedir cualquier doc-Id.
     */
    public Document getDocument(String documentId, String currentUserId) {
        return documents.get(documentId);  // No se verifica currentUserId vs owner
    }

    public record Document(String id, String ownerId, String content) {}
}
