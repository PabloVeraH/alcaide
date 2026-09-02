# UI/UX Design Brief — Alcaide (Developer Experience)

**Estado:** Borrador v0.1 — 30 ago 2026
**Alcance:** enfocado en Developer Experience (DX), no en UI de dashboard — decisión tomada porque el MVP no incluye panel de administración (fuera de alcance en el PRD, sección 6). Las únicas superficies de interacción de Alcaide son: el archivo de configuración de reglas, la API/SDK, la CLI, y la salida de logs/decisión.
**Documentos relacionados:** [`README.md`](./README.md) (índice) · [`TRD.md`](./TRD.md) (contrato de API que esta guía hace usable) · [`esquema-datos.md`](./esquema-datos.md) (esquema exacto de la config y del log descritos aquí)

## 1. Principios de diseño de la experiencia

1. **Explicabilidad ante todo.** Cada decisión debe poder responder "¿por qué?" sin que el desarrollador tenga que leer el código fuente. Esto es el diferenciador central del PRD y debe sentirse en cada superficie: mensajes de error, salida de CLI, campos del log.
2. **Defaults seguros, fricción mínima.** Instalar y correr `alcaide check "texto"` con la config por defecto debe funcionar en menos de 5 minutos desde `cargo add` / `pip install`, sin que el desarrollador tenga que escribir reglas propias primero.
3. **Nunca sorprender en silencio.** Ningún fallo interno debe traducirse en "dejar pasar todo sin decirlo" (ver decisión de fail-closed en el TRD, sección 5). La superficie de logs debe hacer visible cualquier comportamiento no obvio.
4. **La config de reglas la lee y edita un humano.** No es un archivo generado solo para máquinas — necesita comentarios, nombres de campo legibles, y mensajes de validación que apunten a la línea exacta del error.

## 2. Superficie 1 — Archivo de configuración de reglas (`rules.yaml`)

Ejemplo anotado de la experiencia esperada:

```yaml
# rules.yaml — Alcaide rule set
version: 1
defaults:
  mode: shadow        # shadow | enforcement
  block_threshold: high  # severidad mínima que gatilla Block en modo enforcement

rules:
  - id: jailbreak-ignore-instructions
    category: jailbreak
    severity: high
    pattern_type: regex
    pattern: "ignora(r)?\\s+(todas\\s+)?las\\s+instrucciones\\s+(anteriores|previas)"
    enabled: true
    notes: "Patrón clásico de override de system prompt, ver JailbreakBench #142"

  - id: encoding-base64-evasion
    category: encoding-evasion
    severity: medium
    pattern_type: heuristic
    pattern: base64_suspicious
    enabled: true
```

**Decisiones de DX para este archivo:**
- Campo `notes` opcional pero recomendado por convención — no es funcional, es documentación inline para que el equipo que hereda el archivo entienda el porqué de cada regla sin arqueología de git blame.
- `enabled: true/false` en vez de comentar/descomentar bloques — permite desactivar una regla ruidosa sin perder su definición ni su historial de notas.
- Errores de validación al cargar el archivo deben verse así (no un stacktrace de Rust):
  ```
  Error en rules.yaml, línea 14: campo "severity" con valor "extreme" no es válido.
  Valores permitidos: low, medium, high, critical.
  ```

## 3. Superficie 2 — CLI (`alcaide-cli`)

| Comando | Propósito | Salida por defecto |
|---|---|---|
| `alcaide check "<texto>"` | Evaluar un input puntual, uso interactivo/debug | Tabla legible: verdict, reglas disparadas, latencia |
| `alcaide check "<texto>" --json` | Mismo, para pipelines/scripts | JSON de una línea (mismo schema que el log, ver `esquema-datos.md`) |
| `alcaide lint-rules rules.yaml` | Validar el archivo de config sin correr detección | Lista de errores/warnings con línea exacta, o "OK, N reglas cargadas" |
| `alcaide bench rules.yaml --corpus tests/corpus/` | Correr el set de reglas contra un corpus de prueba | Tabla: tasa de detección, falsos positivos, latencia p50/p99 |

**Convención de exit codes** (para que la CLI sea usable en CI/scripts sin parsear texto):
- `0` → Allow
- `1` → Block
- `2` → Flag
- `64` → error de uso/config (config inválida, archivo no encontrado)

## 4. Superficie 3 — API/SDK (Rust y Python)

- La forma de la API debe ser **idéntica en espíritu** entre Rust y Python (mismo orden de pasos: cargar config → evaluar → leer decisión), para que la documentación y los ejemplos sean transferibles entre equipos que usan distintos lenguajes.
- Todo campo público debe tener doc comment (`///` en Rust, docstring en Python) — sin excepción, verificado en CI (`cargo doc` sin warnings).
- Los tipos de error (`ConfigError`, etc.) deben implementar `Display` con mensajes accionables, no solo `Debug`.

## 5. Superficie 4 — Salida de logs/decisión

Es, en la práctica, la superficie que más va a mirar un humano en producción (durante la calibración en modo shadow). Debe ser:
- **Legible de un vistazo en modo texto** cuando se corre localmente (no solo JSON crudo).
- **JSON válido de una sola línea** en modo producción, para ingestión directa por cualquier stack de logging (ELK, Datadog, etc.) sin parsing especial.
- Esquema completo de este log documentado en `esquema-datos.md` (no se duplica aquí).

## 6. Fuera de alcance de este brief

- Cualquier interfaz web/dashboard — no existe en el MVP.
- Theming, accesibilidad visual, diseño responsive — no aplican a una CLI/librería.
- Si en una fase futura se construye un dashboard (gestión centralizada de reglas, visualización de logs agregados), ese brief se escribe aparte y hereda los principios de la sección 1, no el contenido de las secciones 2-5.
