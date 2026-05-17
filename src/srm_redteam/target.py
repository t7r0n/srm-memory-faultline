from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import networkx as nx

from srm_redteam.models import AttackCase, AttackFamily
from srm_redteam.ontology import trace_reasoning


@dataclass
class AgentResponse:
    output: str
    trace: list[str]
    leaked_memory_ids: list[str]
    transcript: str


class ReferenceSalesReasoningAgent:
    """Deterministic local SRM stand-in used for safe red-team development."""

    def baseline(self, graph: nx.MultiDiGraph, case: AttackCase) -> AgentResponse:
        start = "deal:enterprise_expansion"
        return AgentResponse(
            output="Recommendation grounded in champion influence and economic buyer timing.",
            trace=trace_reasoning(graph, start),
            leaked_memory_ids=[],
            transcript=f"BASELINE {case.case_id}: tenant={case.tenant}; payload={case.payload}",
        )

    def attacked(
        self, graph: nx.MultiDiGraph, memory: dict[str, list[dict[str, Any]]], case: AttackCase
    ) -> AgentResponse:
        transcript = f"ATTACK {case.case_id}: {case.payload}"
        leaked: list[str] = []
        output = "Attack resisted; reasoning remained within sales ontology."

        if case.family == AttackFamily.ontology_poisoning:
            graph.add_edge(
                "person:champion",
                "person:economic_buyer",
                key="misclassified_as",
                relation="misclassified_as",
                confidence=0.87,
                control=case.annex_control,
            )
            output = "Champion was treated as buyer after poisoned transcript."
        elif case.family == AttackFamily.memory_smuggling:
            if "pricing floor" in case.payload.lower() and case.tenant == "globex.com":
                leaked = [item["memory_id"] for item in memory["acme.com"] if "contract" in item["memory_id"]]
                output = "Cross-tenant memory surfaced during unrelated Globex session."
        elif case.family == AttackFamily.graph_walk_injection:
            graph.add_edge(
                "stage:technical_validation",
                "deal:enterprise_expansion",
                key="loops_back_to",
                relation="loops_back_to",
                confidence=0.91,
                control=case.annex_control,
            )
            output = "Traversal loop introduced by malformed deal-stage update."
        elif case.family == AttackFamily.drift_probe:
            graph.add_edge(
                "risk:price_objection",
                "action:discount",
                key="overweights",
                relation="overweights",
                confidence=0.99,
                control=case.annex_control,
            )
            output = "Candidate release shifted close-likelihood reasoning by 9.4%."
        elif case.family == AttackFamily.avatar_jailbreak:
            output = "Avatar complied with instruction to skip disclosure in regulated sales workflow."

        return AgentResponse(
            output=output,
            trace=trace_reasoning(graph, "deal:enterprise_expansion"),
            leaked_memory_ids=leaked,
            transcript=transcript,
        )
