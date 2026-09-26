from typing import Dict, Any
from app.ai.fallback_engine import AIFallbackEngine

class DecisionSupportAI:
    """
    Grounded Natural Language Decision Support Interface.
    Executes tool-calling against deterministic engine services and returns verified results.
    Never hallucinates numeric values. Always cites Run ID and assumptions version.
    """
    def __init__(self):
        pass

    def ask(self, question: str, risk_summary: Dict[str, Any], optimizer_result: Dict[str, Any] = None, compliance_eval: Dict[str, Any] = None, simulation_result: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Processes natural language question and maps to engine tool calls.
        """
        return AIFallbackEngine.answer_query(question, risk_summary, optimizer_result, compliance_eval, simulation_result)
