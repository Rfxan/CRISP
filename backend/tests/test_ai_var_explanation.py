import copy
import json
from unittest.mock import patch

import pytest

from app.ai.decision_support import DecisionSupportAI


SUMMARY = {'org': {'eal': 832000, 'var95': 3275000, 'appetite': 120000000,
                   'headroom': 116725000}, 'run_id': 'RUN-board'}
QUESTION = 'Explain our Value at Risk (VaR 95) for the Board of Directors'


@pytest.fixture(autouse=True)
def no_external_model():
    with patch('app.ai.decision_support.llm_config_store.get_config', return_value={'enabled': False}):
        yield


@pytest.mark.parametrize('question', [QUESTION, 'What does VaR95 mean?',
                                    'Explain our 95th percentile annual loss'])
def test_var_answer_explains_annual_percentile_and_board_appetite(question):
    result = DecisionSupportAI().ask(question, SUMMARY)
    answer = result['answer']
    assert '95%' in answer and '5%' in answer
    assert 'annual' in answer
    assert 'at or below' in answer
    assert 'exceed' in answer
    assert 'maximum' in answer
    assert 'within' in answer
    assert '₹32.75 L' in answer and '₹8.32 L' in answer
    assert '₹12.00 Cr' in answer and '₹11.67 Cr' in answer
    assert result['tool_used'] == 'var95_explanation'
    assert result['run_id'] == 'RUN-board'


def test_var_exceeding_appetite_is_not_described_as_within_limits():
    summary = copy.deepcopy(SUMMARY)
    summary['org'].update(appetite=2000000, headroom=-1275000)
    answer = DecisionSupportAI().ask(QUESTION, summary)['answer']
    assert 'exceeds' in answer
    assert '₹12.75 L' in answer
    assert 'within the declared limit' not in answer


@pytest.mark.parametrize('var95', [None, 0])
def test_var_unknown_and_zero_are_not_confused(var95):
    summary = copy.deepcopy(SUMMARY)
    summary['org'].update(var95=var95, headroom=None)
    result = DecisionSupportAI().ask(QUESTION, summary)
    if var95 is None:
        assert 'unknown' in result['answer'].lower()
        assert '95% of' not in result['answer']
    else:
        assert '₹0.00' in result['answer']
        assert 'maximum' in result['answer']


def test_var_unknown_appetite_does_not_invent_a_board_limit():
    summary = copy.deepcopy(SUMMARY)
    summary['org'].update(appetite=None, headroom=None)
    answer = DecisionSupportAI().ask(QUESTION, summary)['answer']
    assert 'No risk-appetite comparison' in answer
    assert '₹12.00 Cr' not in answer


@pytest.mark.parametrize('response', [
    {'answer': 'The maximum possible loss is guaranteed to be 99999999.'},
    {'answer': json.dumps({'claims': [{'metric_id': 'org.var95', 'value': 999}]})},
    {'answer': json.dumps({'claims': [{'metric_id': 'portfolio.cost', 'value': 100}]})},
])
def test_rejected_model_response_retains_correct_board_explanation(response):
    with patch('app.ai.decision_support.llm_config_store.get_config',
               return_value={'enabled': True, 'provider': 'custom', 'api_key': 'test'}), \
         patch('app.ai.decision_support.llm_service.generate_response', return_value=response):
        result = DecisionSupportAI().ask(QUESTION, SUMMARY, optimizer_result={'total_spent': 100})
    assert result['is_llm'] is False
    assert result['fallback_reason']
    assert '₹32.75 L' in result['answer']
    assert '95%' in result['answer']
    assert '99999999' not in result['answer']


def test_model_selected_subset_cannot_remove_var_interpretation():
    response = {'answer': json.dumps({'claims': [{'metric_id': 'org.eal', 'value': 832000}]})}
    with patch('app.ai.decision_support.llm_config_store.get_config',
               return_value={'enabled': True, 'provider': 'custom', 'api_key': 'test'}), \
         patch('app.ai.decision_support.llm_service.generate_response', return_value=response) as model:
        result = DecisionSupportAI().ask(QUESTION, SUMMARY)
    assert result['is_llm'] is True
    assert '₹32.75 L' in result['answer'] and '95%' in result['answer']
    assert any(c['metric_id'] == 'org.var95' for c in result['claims'])
    assert 'compliance.' not in model.call_args.args[1]
