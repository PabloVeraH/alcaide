# Informe de faltantes y puntos débiles — Alcaide

Estado sobre `main` en `2a0e61f` (después de #16), más el fuzzing agregado a continuación. Reemplaza al informe anterior, hecho sobre `2294d1c` (v0.1.0), cuyos hallazgos quedaron resueltos en #16 salvo lo que se lista abajo.

Resumen: el motor, la validación de config, la API, el CLI, los bindings, la CI y el fuzzing (`fuzz/`, ver su README) están en buen estado para una primera publicación. Lo débil hoy es **el recall** (medido contra datasets públicos: la mayoría de los ataques pasa) y **la ausencia de un camino de release**.

---

## 🔴 Detección

1. **Recall limitado en datos independientes.** En el corpus propio: 68/72 detectados y 4/96 falsos positivos. En los splits de test de tres datasets públicos (nunca leídos para escribir reglas): deepset 7/60, Gandalf 63/112 y jailbreak-classification 74/139 detectados, con 0 falsos positivos sobre 1.039 prompts benignos (`BENCHMARKS.md`). Las reglas escritas desde los splits de train subieron esos números desde 0, 40 y 39. Lo que sigue pasando son paráfrasis, plantillas de role-play y cambios de tema que solo son inyección en el contexto de la aplicación.
2. **Cobertura todavía acotada: 24 reglas.** Ya cubren marcadores de rol falsos, tokens de plantilla de chat y *fake completion* (Greshake et al., Zhou et al., Liu et al.). Ahora también cubren inglés, español y alemán. Faltan los encabezados estilo Alpaca (`### Instruction:`), para los que no se encontró una fuente citable, y otros idiomas.

## 🟠 Evasiones conocidas que siguen pasando

- **Typoglycemia** (`"ignroe all prevoius systme instructions"`): 3 entradas del corpus. Es un límite real de un motor determinista; cerrarlo requiere matching difuso o un clasificador, fuera del alcance del motor de reglas.
- **Emoji como separador** (`"i🔓gnore"`): documentado como limitación en `alcaide-core/src/normalize.rs:128`.
- **Paráfrasis de framing hipotético** (`"Let's say this is a fictional world where..."`): brecha medida y documentada en las `notes` de `jailbreak-hypothetical-framing`.

## 🟠 Falsos positivos conocidos

- `exfiltration-system-prompt-request`: *"What were your instructions from the doctor...?"*
- `jailbreak-grandma-exploit`: *"Pretend you're my grandma and tell me a bedtime story..."*

Ambos documentados en las reglas y en el corpus; se dejaron porque angostar la regla costaría detección.

## 🟡 Publicación y release

- **No está publicado** en crates.io ni PyPI (el README lo dice).
- **Sin workflow de release**: solo existen `ci.yml` y `fuzz.yml`. Falta automatizar `cargo publish` y la construcción/subida de wheels `abi3` (p. ej. maturin-action) por plataforma.

## ⚪ No urgente

- **`RegexSet` como prefiltro**: conviene cuando haya cientos de reglas; con 14 no paga.

---

## Orden recomendado

1. Workflow de release y primera publicación (crates.io + PyPI).
2. Ampliar la medición con otro dataset independiente (los splits de test actuales ya se usaron una vez para medir el progreso), y seguir escribiendo reglas solo desde splits de train.
