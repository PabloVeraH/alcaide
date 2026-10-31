"""Type stubs for the `alcaide` extension module (implemented in Rust,
see src/lib.rs -- keep both in sync)."""

from typing import Optional, Tuple, final

@final
class Verdict:
    """The outcome of one evaluation."""

    Allow: Verdict
    """No match at or above the block threshold."""
    Block: Verdict
    """A match at or above the block threshold."""
    Flag: Verdict
    """A match below the block threshold: worth a human's attention."""

@final
class Mode:
    """Whether a detector blocks, or only observes and logs."""

    Shadow: Mode
    """Always returns Allow to the caller; the real result is still logged."""
    Enforcement: Mode
    """Returns the rules' real verdict to the caller."""

@final
class Category:
    """Attack taxonomy a rule belongs to."""

    Jailbreak: Category
    Exfiltration: Category
    RoleplayBypass: Category
    EncodingEvasion: Category
    InjectionGeneric: Category

@final
class Severity:
    """A rule's severity: Low < Medium < High < Critical."""

    Low: Severity
    Medium: Severity
    High: Severity
    Critical: Severity

@final
class MatchDetail:
    """One rule that matched."""

    @property
    def rule_id(self) -> str: ...
    @property
    def category(self) -> Category: ...
    @property
    def severity(self) -> Severity: ...
    @property
    def span(self) -> Tuple[int, int]:
        """(start, end) character offsets of the match in the evaluated
        text: ``text[start:end]`` is the part that triggered the rule."""

@final
class Decision:
    """Result of one `Detector.evaluate` call."""

    @property
    def verdict(self) -> Verdict:
        """The verdict to enforce. Always Allow in shadow mode."""
    @property
    def evaluated_verdict(self) -> Verdict:
        """What the rules determined, before the mode is applied."""
    @property
    def matched_rules(self) -> list[MatchDetail]: ...
    @property
    def latency_us(self) -> int: ...
    @property
    def mode(self) -> Mode: ...
    @property
    def input_truncated(self) -> bool:
        """True if the input exceeded max_input_bytes and only its beginning
        was inspected."""

@final
class Detector:
    """The rule engine. Immutable and thread-safe: build once, share freely."""

    @staticmethod
    def from_config_path(path: str) -> Detector:
        """Loads a rule set from a YAML file.

        Raises OSError if the file can't be read, ValueError if the rule set
        is invalid.
        """
    @staticmethod
    def from_yaml_str(yaml: str) -> Detector:
        """Loads a rule set from YAML text. Raises ValueError if invalid."""
    @staticmethod
    def with_default_rules(mode: Optional[Mode] = None) -> Detector:
        """The bundled curated rule set. It ships in shadow mode; pass
        ``mode=Mode.Enforcement`` to block."""
    def rule_count(self) -> int:
        """Total number of rules in the loaded rule set, enabled or not."""
    def evaluate(self, input: str, request_id: Optional[str] = None) -> Decision:
        """Evaluates `input`. Releases the GIL while evaluating."""
