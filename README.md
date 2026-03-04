# OWASP Top 10:2025 – Ejercicios en Java

Proyecto didáctico con ejemplos de **vulnerabilidades** y **formas correctas** según el [OWASP Top 10:2025](https://owasp.org/Top10/2025/).  
Basado en **JDK 17** (compatible con LTS).

## Requisitos

- **JDK 17** o superior.  
  En `pom.xml` están configurados `maven.compiler.source`, `target` y `release` en 17.

## Estructura

Cada categoría del Top 10 tiene su paquete con dos tipos de clases:

- **`*Vulnerable`**: ejemplos que muestran el riesgo (qué no hacer).
- **`*Secure`**: ejemplos corregidos (buenas prácticas).

| Paquete | OWASP | Descripción |
|--------|--------|-------------|
| `a01_broken_access_control` | A01:2025 | Control de acceso: acceso a recursos sin verificar permisos vs verificación por propietario/admin. |
| `a02_security_misconfiguration` | A02:2025 | Configuración: credenciales hardcodeadas y debug en código vs variables de entorno. |
| `a03_software_supply_chain` | A03:2025 | Cadena de suministro: carga desde URL no verificada vs lista blanca de hosts y HTTPS. |
| `a04_cryptographic_failures` | A04:2025 | Criptografía: MD5/XOR para contraseñas vs PBKDF2 con salt e iteraciones. |
| `a05_injection` | A05:2025 | Inyección: concatenación en consultas/comandos vs parámetros y validación (lista blanca). |
| `a06_insecure_design` | A06:2025 | Diseño: sin rate limit ni bloqueo vs límite de intentos y bloqueo temporal. |
| `a07_authentication_failures` | A07:2025 | Autenticación: contraseñas débiles y sesión sin expiración vs política fuerte y timeout. |
| `a08_data_integrity_failures` | A08:2025 | Integridad: deserialización sin verificar vs verificación de firma (HMAC) del payload. |
| `a09_logging_alerting_failures` | A09:2025 | Logging: no registrar fallos o registrar contraseñas vs auditoría sin datos sensibles y alertas. |
| `a10_mishandling_exceptional_conditions` | A10:2025 | Excepciones: stack traces al usuario vs log interno y mensaje genérico al cliente. |

## Cómo compilar y ejecutar

```bash
# Compilar
mvn compile

# Ejecutar menú de ejemplos (clase Main)
mvn exec:java -q

# Ejecutar tests (cuando existan)
mvn test

# Empaquetar
mvn package
```

La clase `Main` muestra un menú con las 10 opciones del Top 10. Al elegir una, se ejecuta primero el ejemplo **vulnerable** y después el ejemplo **correcto**.

## Si el IDE marca errores en Main.java

El proyecto **compila correctamente** con `mvn compile`. Si Cursor/VS Code sigue mostrando errores en rojo:

1. **Comprobar versión de Java**: En la barra inferior debe aparecer algo como "Java 17". Si no, abre la paleta (Ctrl+Shift+P) → "Java: Configure Java Runtime" y selecciona JDK 17.
2. **Reimportar proyecto Maven**: Ctrl+Shift+P → "Java: Clean Java Language Server Workspace" → Reload and delete. Tras recargar, el IDE volverá a importar el proyecto desde el `pom.xml`.
3. En la carpeta `.vscode/settings.json` está `"java.configuration.updateBuildConfiguration": "automatic"` para que use la configuración de Maven. En `.settings/org.eclipse.jdt.core.prefs` está forzado compliance 17 para el analizador.

## Uso didáctico

1. Revisar la clase `*Vulnerable` de cada paquete para ver el riesgo.
2. Comparar con la clase `*Secure` para ver la mitigación.
3. Adaptar los ejemplos a tu stack (por ejemplo, usar `PreparedStatement` en A05 con JDBC real).

## Referencias

- [OWASP Top 10:2025](https://owasp.org/Top10/2025/)
- [A01 Broken Access Control](https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/)
- [A02 Security Misconfiguration](https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/)
- Y enlaces análogos para A03–A10 en la misma documentación OWASP.

## Licencia

Uso educativo. OWASP Top 10 © OWASP Foundation; consulta la licencia en [owasp.org](https://owasp.org/).
