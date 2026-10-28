# Informe de faltantes y puntos débiles — Alcaide

Estado sobre `main` en `2a0e61f` (después de #16), más el fuzzing agregado a continuación. Reemplaza al informe anterior, hecho sobre `2294d1c` (v0.1.0), cuyos hallazgos quedaron resueltos en #16 salvo lo que se lista abajo.

Resumen: el motor, la validación de config, la API, el CLI, los bindings, la CI y el fuzzing (`fuzz/`, ver su README) están en buen estado para una primera publicación. Lo débil hoy es **la evidencia de detección** (corpus propio, pocas reglas) y **la ausencia de un camino de release**.

---

## 🔴 Detección

1. **Corpus propio y sobreajustado.** 58/62 maliciosos detectados y 3/88 falsos positivos (`BENCHMARKS.md`), pero las reglas se afinaron contra ese mismo corpus de 150 prompts. Falta evaluar contra datasets públicos independientes (deepset/prompt-injections, JailbreakBench, HackAPrompt) con un conjunto de validación separado que no se use para afinar.
2. **Cobertura todavía acotada: 18 reglas.** Ya cubren marcadores de rol falsos, tokens de plantilla de chat y *fake completion* (Greshake et al., Zhou et al., Liu et al.). Faltan los encabezados estilo Alpaca (`### Instruction:`) y "new instructions:", para los que no se encontró una fuente citable, y reglas en otros idiomas aparte de inglés y español.

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
2. Evaluación contra un dataset público con split de validación; publicar los números en `BENCHMARKS.md` tal como salgan.
3. Reglas nuevas guiadas por esa evaluación, cada una con su entrada en el corpus y su probe de precisión.
