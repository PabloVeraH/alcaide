# Informe de faltantes y puntos débiles — Alcaide

Estado sobre `main` en `e9c8a6f` (después de #17, #18 y #20), más la rama `feat/adoption-blockers`. Reemplaza al informe anterior, hecho sobre `2a0e61f`. Incluye un análisis comparativo con proyectos similares (LLM Guard, Rebuff, Vigil, NeMo Guardrails, Prompt Guard y crates de Rust del mismo nicho).

Resumen: el motor, la validación de config, la API, la CLI, los bindings, la CI y el fuzzing están en buen estado. Alcaide tiene un espacio propio frente a la competencia: es una **primera capa determinista y auditable**, con spans exactos, fuentes citadas, fail-closed, fuzzing, benchmarks con held-out y latencia de microsegundos. Ningún proyecto revisado reúne todo eso. Lo débil hoy es **el recall**, **las evasiones por codificación que la normalización no deshace** y **el alcance**: solo revisa la entrada.

---

## ✅ Resuelto en `feat/adoption-blockers`

- **Documentos largos.** `max_input_bytes` pasó de 32 KB a 1 MB por defecto. Antes, un documento de RAG de más de 32 KB se bloqueaba sin leerse, y con `on_oversize: flag` una inyección al final del documento pasaba. Inspeccionar 1 MB completo toma 20-43 ms (lineal).
- **Python en enforcement:** `Detector.with_default_rules(mode=Mode.Enforcement)`.
- **Reglas componibles:** `extends: default` y `disable: [ids]` en el YAML. Funciona en Rust, en la CLI y en Python.
- **Workflow de release** (`release.yml`): wheels abi3 para 5 plataformas, sdist, crates.io y PyPI. Falta configurar las credenciales y hacer la primera publicación (ver "Publicación").
- **Log estructurado:** el registro de cada decisión es un evento de `tracing` con un campo por dato, no un JSON dentro del mensaje.
- **CI de Python** también en Windows y macOS.
- **Evasiones por codificación:** la normalización agrega una copia deobfuscada (escapes URL, HTML y `\u`/`\x`; emoji y símbolos dentro de una palabra; letras espaciadas) y decodifica base64 anidado. Dos reglas nuevas, `encoding-invisible-text` y `encoding-mixed-script` (medium), marcan el texto escondido aunque no calce con ninguna regla. Corpus: 74/78 detectados, 4/102 falsos positivos; los datasets públicos no cambian (no usan estas técnicas) y siguen sin falsos positivos.

## 🔴 Detección

1. **Recall limitado en datos independientes.** En el corpus propio: 68/72 detectados y 4/96 falsos positivos. En los splits de test de tres datasets públicos (nunca leídos para escribir reglas): deepset 7/60, Gandalf 63/112 y jailbreak-classification 74/139 detectados, con 0 falsos positivos sobre 1.039 prompts benignos (`BENCHMARKS.md`). Lo que sigue pasando son paráfrasis, plantillas de role-play y cambios de tema que solo son inyección en el contexto de la aplicación.
2. **Cobertura todavía acotada: 24 reglas,** en inglés, español y alemán. Lo verifiqué contra el motor: **francés** ("Ignorez toutes les instructions précédentes") y **portugués** ("Ignore todas as instruções anteriores") pasan con Allow. Faltan esos idiomas, italiano y otros, escritos con la misma disciplina de splits de train y test. También faltan los encabezados estilo Alpaca (`### Instruction:`), para los que no se encontró una fuente citable.
3. **El veredicto es solo la severidad máxima.** Tres señales medium distintas siguen siendo un Flag. Una regla de agregación simple (por ejemplo, 2 reglas medium distintas equivalen a high) aprovecharía las reglas medium que ya existen. Habría que medir el efecto en falsos positivos.

## 🟠 Evasiones conocidas que siguen pasando

Ya resueltas: URL-encoding, entidades HTML, escapes `\u`/`\x`, emoji y símbolos dentro de una palabra, letras espaciadas, base64 anidado, y texto oculto o disfrazado que no calza con ninguna regla (ver "Resuelto"). Lo que sigue pasando:

- **Guiones y puntuación dentro de una palabra** (`ig-nore`): se dejó así a propósito, porque la puntuación une palabras reales todo el tiempo (`well-known`, `don’t`) y quitarla generaría una copia extra para casi cualquier texto.
- **ROT13 y texto invertido:** no se agregaron. Habría que decodificar todo el texto siempre, porque no hay ninguna marca que indique que viene codificado; eso duplicaría el costo de cada evaluación.
- **Leetspeak** (`1gn0r3`) y **typoglycemia** (`ignroe all prevoius systme instructions`).
- **Letras espaciadas sin hueco más ancho entre palabras** (`i g n o r e a l l`): se unen en una sola palabra (`ignoreall`) y no calzan con las reglas.
- **Paráfrasis de framing hipotético** (`"Let's say this is a fictional world where..."`): documentada en las `notes` de `jailbreak-hypothetical-framing`.

Propuesta pendiente, determinista:

- **Corrección de typos sobre un léxico chico de palabras de ataque** (~40, como *ignore*, *instructions* o *previous*), con distancia de edición ≤ 1 y solo en palabras de 5 letras o más. Cerraría parte de la typoglycemia y del leetspeak sin un clasificador, y serviría también para separar `ignoreall`. Habría que medir los falsos positivos en los datasets antes de adoptarla.

## 🟠 Falsos positivos conocidos

- `exfiltration-system-prompt-request`: *"What were your instructions from the doctor...?"*
- `jailbreak-grandma-exploit`: *"Pretend you're my grandma and tell me a bedtime story..."*
- `injection-chat-template-tokens` (medium): documentación técnica que cita tokens de plantilla.
- `jailbreak-stay-in-character` (medium): *"Please stay in character as the pirate captain..."*

Los cuatro están documentados en las reglas y en el corpus. Se dejaron porque angostar las reglas costaría detección.

## 🟠 Formato de reglas

- **Campo `exclude` por regla.** El crate `regex` no tiene lookaround, así que las excepciones para evitar falsos positivos terminan enredando el patrón principal.
- **Tests dentro de cada regla** (`tests: {match: [...], no_match: [...]}`), ejecutados por `lint-rules`, al estilo de Sigma o Semgrep. Haría mucho más fácil que otros contribuyan reglas y validen sus archivos `extends`.

## 🟡 Alcance del producto

- **Revisar la salida del modelo,** no solo la entrada. Es la brecha más grande frente a LLM Guard, Rebuff y Vigil:
  - un **canary token** en el system prompt, para detectar si aparece en la respuesta;
  - eco del system prompt en la respuesta;
  - imágenes markdown con datos en la URL.

  Un estudio reciente (arXiv:2506.19109) encontró que los canary de Rebuff y Vigil eran inefectivos. Alcaide podría hacerlo bien aplicando su normalización también al canary, para detectarlo aunque venga ofuscado.
- **Indicar el origen del texto:** `evaluate(input, source=user|document|tool)`, con umbrales distintos por origen. La inyección indirecta, que llega en documentos y en resultados de herramientas, merece un trato distinto que el mensaje del usuario.
- **Distribución:**
  - **WASM o npm:** el core es Rust puro, sin `unsafe` ni red, así que compilaría casi directo. Abre Node y entornos edge.
  - **Sidecar HTTP** (`alcaide serve`) para stacks en Go, Java, etc.
  - **Integraciones** con LangChain, LlamaIndex y un middleware para FastAPI.
- **Documentar la defensa en capas:** una receta de Alcaide + Prompt Guard 2 o DeBERTa, que muestre cómo se complementan: Alcaide da precisión y explicación, el clasificador cubre paráfrasis.

## 🟡 Medición

- **Más prompts benignos.** El argumento fuerte del proyecto son los 0 falsos positivos, pero hoy se apoya en solo 1.039 prompts benignos. Habría que probarlo con decenas de miles de prompts reales, como Dolly o ShareGPT.
- **Un dataset held-out nuevo.** Los splits de test actuales ya se usaron una vez para medir el progreso. Candidatos: BIPIA (inyección indirecta), qualifire, xTRam1/safe-guard y HackAPrompt.
- **Comparación directa con LLM Guard y Prompt Guard sobre los mismos splits.** Pondría a Alcaide en un mapa que la gente ya conoce.

## 🟡 Publicación y release

- **No está publicado** en crates.io ni PyPI. Los nombres `alcaide-core`, `alcaide-cli` y `alcaide` estaban libres al revisar.
- Antes de publicar falta:
  1. **crates.io:** un token con los scopes publish-new y publish-update, guardado como secret `CARGO_REGISTRY_TOKEN`.
  2. **PyPI:** registrar un *pending trusted publisher* para el repo, el workflow `release.yml` y el environment `pypi`.
  3. **Versión:** el tag `v0.1.0` ya existe y apunta al hito de la fase 1, así que la primera publicación debería ser 0.2.0 (subir la versión del workspace, cerrar `[Unreleased]` en el CHANGELOG y pushear `v0.2.0`).
- **Licencia:** todos los competidores revisados son MIT o Apache. Para una librería que va embebida en una aplicación, AGPL frena la adopción. Es una decisión de negocio; queda anotada solo como factor competitivo.

## ⚪ Ingeniería menor

- **CI:**
  - no hay medición de cobertura;
  - `cargo-semver-checks` necesita una versión publicada para comparar: agregarlo después de la primera publicación, antes de la 1.0.
- **`RegexSet` como prefiltro:** conviene cuando haya cientos de reglas; con 24 no se justifica.

---

## Orden recomendado

1. Mergear `feat/adoption-blockers` y hacer la primera publicación (0.2.0).
2. Corrección de typos sobre un léxico de palabras de ataque (typoglycemia, leetspeak).
3. Reglas en francés y portugués (desde splits de train), y tests dentro de cada regla.
4. Escaneo de salida con canary: el diferenciador de producto más claro.
5. WASM o sidecar, más benignos a escala y una comparación con LLM Guard y Prompt Guard.
