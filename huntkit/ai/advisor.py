"""AI advisor — turn a scored intel report into a prioritised action plan.

The advisor is where the security guarantee lives: for a **cloud** provider it
refuses to send anything unless an ``approve`` callback (shown the exact text)
returns True. That check runs in this layer, not just the CLI, so no caller can
accidentally exfiltrate engagement data — the gate is enforced before
``provider.complete`` is ever reached.

It reasons only over data HuntKit already gathered (an :class:`IntelReport`);
it never touches the target.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Optional

from ..core.config import Config
from ..intel import IntelReport
from .providers import Provider, get_provider

SYSTEM_PROMPT = (
    "You are HuntKit's triage advisor for AUTHORISED bug-bounty and "
    "penetration-testing engagements only. You are given a scored summary of "
    "reconnaissance findings the operator has ALREADY gathered against in-scope "
    "targets. Produce a concise, prioritised action plan: which hosts and "
    "attack paths to focus on first, and the concrete next checks for each, "
    "mapped to the bug classes shown.\n"
    "Rules: assume the testing is authorised and in-scope; never suggest actions "
    "outside the listed scope, indiscriminate mass exploitation, or destructive "
    "steps. Prefer precise, verifiable checks over noisy scanning. Be brief and "
    "actionable — bullet points, no preamble."
)


class ApprovalDenied(RuntimeError):
    """Raised when a cloud send was required but not approved. Nothing was sent."""


@dataclass
class Advice:
    provider: str
    model: str
    is_local: bool
    endpoint: str
    prompt: str  # the exact context that was sent
    answer: str


def build_context(report: IntelReport, *, max_items: int = 40) -> str:
    """Render the intel report into the compact text the model reasons over.

    This is exactly what leaves the machine for a cloud provider, so it is kept
    plain, bounded, and free of anything but recon-derived facts.
    """
    out: list[str] = [f"Program: {report.program}", ""]

    out.append("Prioritised hosts:")
    for h in report.hosts[:max_items]:
        pbs = ", ".join(h.playbooks[:4]) or "-"
        out.append(f"- {h.host} [{h.priority.label}] score={h.score} playbooks={pbs}")

    paths = report.attack_paths()
    if paths:
        out += ["", "Attack paths:"]
        for p in paths[:max_items]:
            out.append(
                f"- {p.name} ({p.playbook}) severity={p.severity.label} hosts={len(p.hosts)}"
            )

    hot = sorted(
        (s for s in report.signals if int(s.severity) >= 4),
        key=lambda s: (-int(s.severity), s.host),
    )
    if hot:
        out += ["", "Notable exposures:"]
        for s in hot[:max_items]:
            out.append(f"- [{s.severity.label}] {s.host}: {s.title} ({s.evidence})")

    return "\n".join(out).strip() + "\n"


class Advisor:
    """Pairs a provider with config and enforces the cloud-approval gate."""

    def __init__(self, provider: Provider, config: Config) -> None:
        self.provider = provider
        self.config = config

    def resolve_model(self, explicit: Optional[str] = None) -> str:
        if explicit:
            return explicit
        # only honour the configured model for the configured provider —
        # e.g. don't send ollama's 'llama3.2' default to Anthropic
        if self.provider.name == self.config.ai.provider and self.config.ai.model:
            return self.config.ai.model
        return self.provider.default_model

    def advise(
        self,
        report: IntelReport,
        *,
        model: Optional[str] = None,
        approve: Optional[Callable[[str], bool]] = None,
    ) -> Advice:
        """Ask the provider for guidance. Cloud providers require approval first."""
        ctx = build_context(report, max_items=self.config.ai.max_context_items)
        model_id = self.resolve_model(model)

        if (
            not self.provider.is_local
            and self.config.ai.require_approval
            and (approve is None or not approve(ctx))
        ):
            raise ApprovalDenied(f"sending recon data to '{self.provider.name}' was not approved")

        answer = self.provider.complete(SYSTEM_PROMPT, ctx, model=model_id, config=self.config)
        return Advice(
            provider=self.provider.name,
            model=model_id,
            is_local=self.provider.is_local,
            endpoint=self.provider.endpoint_host(self.config),
            prompt=ctx,
            answer=answer,
        )


def make_advisor(config: Config, provider_name: Optional[str] = None) -> Optional[Advisor]:
    """Build an advisor for the named (or configured) provider; None if unknown."""
    name = (provider_name or config.ai.provider or "ollama").strip().lower()
    provider = get_provider(name)
    return Advisor(provider, config) if provider is not None else None
