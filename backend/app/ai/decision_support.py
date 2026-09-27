"""
CRISP Grounded Decision Support AI.
Routes questions through actual multi-provider LLMs (Gemini, OpenAI, Groq, Claude, Ollama)
grounded in verified figures from the FAIR Monte Carlo engine and PuLP ILP solver.
Gracefully falls back to deterministic rule synthesis if no LLM API key is configured.
"""

import logging
from typing import Dict, Any, Optional

from app.ai.fallback_engine import AIFallbackEngine
from app.ai.llm_config_store import llm_config_store
from app.ai.llm_service import llm_service

logger = logging.getLogger(__name__)


def _format_inr(val: Optional[float]) -> str:
    if val is None or val == 0:
        return "₹0"
    abs_v = abs(val)
    sign = "-" if val < 0 else ""
    if abs_v >= 10_000_000:
        return f"{sign}₹{abs_v / 10_000_000:.2f} Cr"
    elif abs_v >= 100_000:
        return f"{sign}₹{abs_v / 100_000:.2f} L"
    else:
        return f"{sign}₹{abs_v:,.2f}"


class DecisionSupportAI:
    def __init__(self):
        pass

    def build_grounding_context(
        self,
        risk_summary: Dict[str, Any],
        optimizer_result: Optional[Dict[str, Any]] = None,
        compliance_eval: Optional[Dict[str, Any]] = None,
        simulation_result: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Synthesizes live calculations into a rigorous factsheet for the LLM.
        """
        run_id = risk_summary.get("run_id", "RUN-ACTIVE")
        assumptions_ver = risk_summary.get("assumptions_version", 4)
        org = risk_summary.get("org", {})
        eal = org.get("eal", 0.0) or 0.0
        var95 = org.get("var95", 0.0) or 0.0
        var99 = org.get("var99", 0.0) or 0.0
        appetite = org.get("appetite", 120_000_000.0) or 120_000_000.0
        headroom = org.get("headroom", 0.0) or (appetite - var95)
        drivers = risk_summary.get("drivers", [])

        drivers_lines = []
        for i, d in enumerate(drivers[:5], 1):
            d_id = d.get("id", "Unknown")
            d_asset = d.get("asset_name") or d.get("asset_id", "Unknown Asset")
            d_marginal = d.get("marginal_eal", 0.0)
            d_cvss = d.get("cvss", "N/A")
            d_sev = d.get("severity", "High")
            d_epss = d.get("epss", 0.0)
            d_kev = "YES (CISA KEV Listed)" if d.get("in_kev") else "No"
            drivers_lines.append(
                f"  {i}. {d_id} on {d_asset}: Marginal EAL = {_format_inr(d_marginal)} (₹{d_marginal:,.2f}), "
                f"CVSS = {d_cvss} ({d_sev}), EPSS = {d_epss:.1%}, KEV = {d_kev}"
            )
        drivers_text = "\n".join(drivers_lines) if drivers_lines else "  No active finding drivers."

        # Optimizer block
        opt_text = "Not queried"
        if optimizer_result:
            opt_plan = optimizer_result.get("plan", optimizer_result)
            spent = opt_plan.get("total_spent", 0.0)
            red = opt_plan.get("total_reduction", 0.0)
            target_b = opt_plan.get("budget", 10_000_000.0)
            rem_eal = opt_plan.get("remaining_eal", max(0.0, eal - red))
            rosi = opt_plan.get("overall_rosi", 0.0)
            actions = [a.get("name") or a.get("cve_id") or a.get("id") for a in opt_plan.get("all_actions", [])[:5]]
            benchmark = optimizer_result.get("benchmark", {})
            outperf = benchmark.get("headline", {}).get("outperformance_vs_cvss_pct", 0.0)

            opt_text = (
                f"- Budget Constraint: {_format_inr(target_b)} (₹{target_b:,.0f})\n"
                f"- Optimal Spend: {_format_inr(spent)}\n"
                f"- Expected Loss Reduction: {_format_inr(red)}\n"
                f"- Remaining EAL: {_format_inr(rem_eal)}\n"
                f"- Portfolio ROSI: {rosi}x\n"
                f"- Primary Recommended Actions: {', '.join(actions) if actions else 'None'}\n"
                f"- Mathematical Outperformance vs Naive CVSS: +{outperf}% higher risk reduction"
            )

        # Compliance block
        comp_text = "Not evaluated"
        if compliance_eval:
            fw_name = compliance_eval.get("framework_name", "SEBI CSCRF")
            cov = compliance_eval.get("overall_coverage_pct", 0.0)
            comp_cnt = compliance_eval.get("compliant_controls", 0)
            tot_cnt = compliance_eval.get("total_controls_mapped", 0)
            gaps = compliance_eval.get("gaps_count", 0)
            sebi_info = compliance_eval.get("sebi_6hour_readiness", {})
            sebi_score = sebi_info.get("readiness_score_pct", 0.0)
            sebi_stat = sebi_info.get("status", "EVALUATING")
            sebi_recom = sebi_info.get("recommendation", "")

            comp_text = (
                f"- Framework: {fw_name}\n"
                f"- Overall Control Coverage: {cov}% ({comp_cnt}/{tot_cnt} controls compliant)\n"
                f"- Identified Deficiencies: {gaps} gaps\n"
                f"- SEBI 6-Hour Incident Notification Readiness: {sebi_score}% ({sebi_stat})\n"
                f"- SEBI Advisory: {sebi_recom}"
            )

        # Simulation block
        sim_text = "No counterfactual active"
        if simulation_result:
            d_eal = simulation_result.get("delta", {}).get("eal_reduction", 0.0)
            d_pct = simulation_result.get("delta", {}).get("pct_eal_reduction", 0.0)
            d_var = simulation_result.get("delta", {}).get("var95_reduction", 0.0)
            cod = simulation_result.get("cost_of_delay", {}).get("per_week_inr", 0.0)
            applied = simulation_result.get("applied_actions", ["Scenario Intervention"])

            sim_text = (
                f"- Intervention: {'; '.join(applied)}\n"
                f"- Immediate EAL Reduction: {_format_inr(d_eal)} ({d_pct}% drop)\n"
                f"- VaR95 Reduction: {_format_inr(d_var)}\n"
                f"- Cost of Delay (Per Week): {_format_inr(cod)} / week"
            )

        system_context = f"""You are the CRISP AI Executive Decision Support Assistant for Cyber Risk Quantification (CRQ).
You advise the CISO, CFO, and Board of Directors on financial cyber exposure, budget allocation, and regulatory compliance.
CRISP replaces vague qualitative heatmaps (Red/Amber/Green) with audited financial mathematics (FAIR Monte Carlo simulation & PuLP Integer Linear Programming).

=== VERIFIED LIVE AUDITED METRICS (Run ID: {run_id}, Assumptions: v{assumptions_ver}) ===
• Expected Annual Loss (EAL): {_format_inr(eal)} (₹{eal:,.2f})
• 95% Value at Risk (VaR 95): {_format_inr(var95)} (₹{var95:,.2f}) [1-in-20 year financial loss ceiling]
• 99% Value at Risk (VaR 99): {_format_inr(var99)}
• Board Risk Appetite: {_format_inr(appetite)} [Status: {'EXCEEDED' if headroom < 0 else 'WITHIN APPETITE'}, Headroom: {_format_inr(headroom)}]

=== TOP MARGINAL RISK DRIVERS ===
{drivers_text}

=== PU-LP INTEGER LINEAR PROGRAMMING OPTIMIZATION ===
{opt_text}

=== REGULATORY COMPLIANCE & INCIDENT READINESS ===
{comp_text}

=== COUNTERFACTUAL WHAT-IF SIMULATION ===
{sim_text}

=== CRITICAL INSTRUCTIONS ===
1. ALWAYS ground your answers in the figures above. Reference the active Run ID ({run_id}) and state specific numbers in ₹ INR (Crores / Lakhs where appropriate).
2. NEVER invent numbers that conflict with the verified metrics above.
3. Provide strategic, board-level executive reasoning: explain the financial 'why' behind the risks, the return on investment (ROSI), and remediation urgency.
4. Format your answer with clean markdown bullet points, bold key figures, and concise executive takeaways."""

        return system_context

    def ask(
        self,
        question: str,
        risk_summary: Dict[str, Any],
        optimizer_result: Optional[Dict[str, Any]] = None,
        compliance_eval: Optional[Dict[str, Any]] = None,
        simulation_result: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Executes user query: runs actual LLM if configured and enabled, otherwise falls back to deterministic synthesis.
        """
        run_id = risk_summary.get("run_id", "RUN-ACTIVE")
        assumptions_ver = risk_summary.get("assumptions_version", 4)

        # Check LLM configuration
        cfg = llm_config_store.get_config()
        is_llm_ready = cfg.get("enabled", True) and (bool(cfg.get("api_key")) or cfg.get("provider") == "ollama")

        if is_llm_ready:
            try:
                system_context = self.build_grounding_context(
                    risk_summary,
                    optimizer_result,
                    compliance_eval,
                    simulation_result
                )

                logger.info(f"Dispatching query to LLM provider: {cfg.get('provider')} ({cfg.get('model')})")
                res = llm_service.generate_response(question, system_context, cfg)

                return {
                    "query": question,
                    "answer": res["answer"],
                    "tool_used": "llm_grounded_synthesis",
                    "tool_args": {"provider": res["provider"], "model": res["model"]},
                    "run_id": run_id,
                    "assumptions_version": assumptions_ver,
                    "sources": [
                        "FAIR Monte Carlo Engine",
                        "PuLP ILP Optimizer",
                        "SEBI CSCRF Engine",
                        f"LLM: {res['provider'].upper()} ({res['model']})"
                    ],
                    "is_llm": True,
                    "llm_provider": res["provider"],
                    "llm_model": res["model"],
                    "latency_ms": res.get("latency_ms", 0)
                }
            except Exception as e:
                logger.warning(f"LLM invocation failed: {e}. Falling back to deterministic engine.")
                fallback_res = AIFallbackEngine.answer_query(
                    question,
                    risk_summary,
                    optimizer_result,
                    compliance_eval,
                    simulation_result
                )
                fallback_res["is_llm"] = False
                fallback_res["fallback_reason"] = f"LLM error: {str(e)}"
                fallback_res["sources"].append(f"Fallback Engine (LLM unreachable: {str(e)[:60]}...)")
                return fallback_res

        # Fallback to deterministic rules when no LLM is configured
        fallback_res = AIFallbackEngine.answer_query(
            question,
            risk_summary,
            optimizer_result,
            compliance_eval,
            simulation_result
        )
        fallback_res["is_llm"] = False
        fallback_res["llm_provider"] = "deterministic"
        fallback_res["llm_model"] = "CRISP Grounded Rules Engine"
        return fallback_res
