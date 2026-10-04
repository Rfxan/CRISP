import json
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from app.ai.decision_support import DecisionSupportAI
from app.compliance.evidence import reporting_readiness


SUMMARY = {'org': {'eal': 832000, 'var95': 3275000, 'appetite': 120000000,
                   'headroom': 116725000}, 'run_id': 'RUN-test', 'assumptions_version': '5.0'}
QUESTION = 'Are we compliant with SEBI 6-hour reporting?'


@pytest.fixture(autouse=True)
def no_external_model():
    with patch('app.ai.decision_support.llm_config_store.get_config', return_value={'enabled': False}):
        yield


def compliance(hours=None):
    exercises = []
    if hours is not None:
        incident = datetime.now(timezone.utc) - timedelta(hours=12)
        exercises = [{'id': 'exercise-1', 'incident_at': incident.isoformat(),
                      'detected_at': (incident + timedelta(minutes=10)).isoformat(),
                      'escalated_at': (incident + timedelta(minutes=20)).isoformat(),
                      'reported_at': (incident + timedelta(hours=hours)).isoformat(),
                      'evidence_ref': 'Recorded exercise'}]
    return {'framework_name': 'SEBI CSCRF', 'evidence_completeness_pct': 12.5,
            'assessed_compliance_pct': 0, 'compliant_controls': 0, 'total_controls_mapped': 16,
            'sebi_6hour_readiness': reporting_readiness(exercises)}


@pytest.mark.parametrize('question', [QUESTION, 'Can we report incidents within six hours?',
                                    'Show our incident reporting readiness'])
def test_reporting_question_with_no_exercise_explains_missing_evidence(question):
    result = DecisionSupportAI().ask(question, SUMMARY, compliance_eval=compliance())
    assert 'NOT VERIFIED' in result['answer']
    assert 'incident, detection, escalation and reporting timestamps' in result['answer']
    assert 'Expected annual loss' not in result['answer']
    assert all(c['metric_id'].startswith('compliance.reporting.') for c in result['claims'])
    assert result['tool_used'] == 'reporting_readiness'
    assert 'Recorded reporting exercises' in result['sources']


@pytest.mark.parametrize('hours,status,minutes', [(3, 'READY', 180), (8, 'AT RISK', 480)])
def test_reporting_answers_follow_measured_exercise(hours, status, minutes):
    result = DecisionSupportAI().ask(QUESTION, SUMMARY, compliance_eval=compliance(hours))
    assert status in result['answer']
    assert 'regulatory compliance' in result['answer']
    facts = {c['metric_id']: c['value'] for c in result['claims']}
    assert facts['compliance.reporting.longest_minutes'] == minutes
    assert facts['compliance.reporting.exercise_count'] == 1
    assert 'Expected annual loss' not in result['answer']


@pytest.mark.parametrize('model_answer', [
    'Yes, compliant; guaranteed reporting in one minute.',
    json.dumps({'claims': [{'metric_id': 'org.eal', 'value': 832000}]}),
    json.dumps({'claims': [{'metric_id': 'compliance.reporting.score', 'value': 100}]}),
])
def test_failed_or_irrelevant_model_response_keeps_reporting_answer(model_answer):
    with patch('app.ai.decision_support.llm_config_store.get_config',
               return_value={'enabled': True, 'provider': 'custom', 'api_key': 'test'}), \
         patch('app.ai.decision_support.llm_service.generate_response', return_value={'answer': model_answer}):
        result = DecisionSupportAI().ask(QUESTION, SUMMARY, compliance_eval=compliance())
    assert 'NOT VERIFIED' in result['answer']
    assert result['is_llm'] is False
    assert result['fallback_reason']
    assert 'Expected annual loss' not in result['answer']


def test_valid_model_receives_reporting_facts_and_server_renders_status():
    answer = json.dumps({'claims': [{'metric_id': 'compliance.reporting.score', 'value': None}]})
    with patch('app.ai.decision_support.llm_config_store.get_config',
               return_value={'enabled': True, 'provider': 'custom', 'api_key': 'test'}), \
         patch('app.ai.decision_support.llm_service.generate_response', return_value={'answer': answer}) as model:
        result = DecisionSupportAI().ask(QUESTION, SUMMARY, compliance_eval=compliance())
    context = model.call_args.args[1]
    assert 'compliance.reporting.score' in context
    assert 'NOT VERIFIED' in context
    assert 'org.eal' not in context
    assert result['is_llm'] is True
    assert 'NOT VERIFIED' in result['answer']


def test_provider_failure_preserves_reporting_evidence():
    with patch('app.ai.decision_support.llm_config_store.get_config',
               return_value={'enabled': True, 'provider': 'custom', 'api_key': 'test'}), \
         patch('app.ai.decision_support.llm_service.generate_response', side_effect=RuntimeError('Provider unavailable')):
        result = DecisionSupportAI().ask(QUESTION, SUMMARY, compliance_eval=compliance(8))
    assert 'AT RISK' in result['answer']
    assert result['fallback_reason']
    assert result['is_llm'] is False
    assert 'Expected annual loss' not in result['answer']


def test_reporting_readiness_does_not_require_quantified_financial_loss():
    result = DecisionSupportAI().ask(QUESTION, {'org': {'eal': None}}, compliance_eval=compliance(3))
    assert 'READY' in result['answer']
    assert 'Financial exposure is unknown' not in result['answer']


def test_general_compliance_question_uses_assessments_instead_of_financial_metrics():
    result = DecisionSupportAI().ask('Are we compliant with SEBI?', SUMMARY, compliance_eval=compliance())
    assert 'curated' in result['answer'].lower()
    assert 'review' in result['answer'].lower()
    assert 'Expected annual loss' not in result['answer']
    assert any(c['metric_id'] == 'compliance.assessed' and c['value'] == 0 for c in result['claims'])
