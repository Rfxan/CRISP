import copy
import json
import numpy as np
import pytest
from app.core.config import DATA_DIR
from app.engine.fair_engine import FAIREngine
from app.engine.whatif import WhatIfSimulator, apply_actions
from app.engine.model import finding_key
from app.engine.distributions import sample_poisson
from app.engine.optimizer import InvestmentOptimizer


@pytest.fixture
def snapshot():
    value = json.loads((DATA_DIR / 'seed_snapshot.json').read_text(encoding='utf-8'))
    value['controls_catalog'] = json.loads((DATA_DIR / 'controls_catalog.json').read_text(encoding='utf-8'))
    return value


@pytest.mark.parametrize('budget', [0, 500_000, 10_000_000])
def test_optimizer_and_every_benchmark_use_same_simulator(snapshot, budget):
    engine = FAIREngine(trials=1000, seed=42)
    optimizer = InvestmentOptimizer(snapshot['controls_catalog'], snapshot['findings'], snapshot['cve_intel'], snapshot=snapshot, engine=engine)
    benchmark = optimizer.run_benchmark(budget=budget)
    simulator = WhatIfSimulator(engine)
    for strategy in benchmark['strategies']:
        replay = simulator.simulate_intervention(snapshot, strategy['actions'], seed=42)
        assert strategy['remaining_eal'] == replay['post_intervention']['eal']
        assert strategy['eal_reduction'] == replay['delta']['eal_reduction']
        assert strategy['spend'] <= budget
    assert sum(s['action_universe'] == 'patches and controls' for s in benchmark['strategies']) == 2
    plan = optimizer.optimize(budget=budget)
    assert plan['remaining_eal'] == simulator.simulate_intervention(snapshot, plan['actions'], 42)['post_intervention']['eal']
    assert all(a['estimated_reduction'] is None for a in plan['all_actions'])
    assert benchmark['reproducibility']['trials'] == 1000
    with pytest.raises(ValueError): optimizer.optimize(budget=-1)


def test_missing_scan_completed_scan_and_final_patch(snapshot):
    engine = FAIREngine(trials=1000)
    snapshot['findings'] = snapshot['findings'][:1]
    result = WhatIfSimulator(engine).simulate_intervention(snapshot, [{'type':'patch_finding','target_id':finding_key(snapshot['findings'][0])}])
    assert result['status'] == 'REMEDIATED'
    assert result['post_intervention']['eal'] is not None
    snapshot['findings'] = []
    assert engine.run(snapshot)['org']['eal'] is None
    snapshot['assessment_state'] = {'status':'completed'}
    assert engine.run(snapshot)['org']['eal'] is not None


def test_unique_driver_keys_and_exact_removal_benefit(snapshot):
    engine = FAIREngine(trials=1000)
    first = snapshot['findings'][0]
    other = copy.deepcopy(first)
    other['asset_id'] = next(a['id'] for a in snapshot['assets'] if a['id'] != first['asset_id'])
    snapshot['findings'] = [first, other]
    result = engine.run(snapshot)
    assert len({d['id'] for d in result['drivers']}) == 2
    for driver in result['drivers']:
        actions = [{'type':'patch_finding','target_id':driver['id']}]
        modified, _ = apply_actions(snapshot, actions)
        assert len(modified['findings']) == 1
        replay = WhatIfSimulator(engine).simulate_intervention(snapshot, actions)
        assert driver['marginal_eal'] == pytest.approx(replay['delta']['eal_reduction'], abs=.02)
    assert len(snapshot['findings']) == 2


def test_shared_trial_intensity_is_preserved():
    rates = np.r_[np.zeros(1000), np.full(1000, 20.)]
    result = sample_poisson(rates, size=2000, rng=np.random.default_rng(42))
    assert np.all(result[:1000] == 0)
    assert result[1000:].mean() == pytest.approx(20, abs=1)


def test_zero_exposure_and_irrelevant_findings_do_not_inflate_risk(snapshot):
    engine = FAIREngine(trials=1500)
    for asset in snapshot['assets']: asset['exposure_probability'] = 0
    baseline = engine.run(snapshot, {'calculate_drivers':False})
    removed = copy.deepcopy(snapshot)
    removed['findings'] = []
    removed['assessment_state'] = {'status':'completed'}
    assert baseline['org']['eal'] == engine.run(removed, {'calculate_drivers':False})['org']['eal']
    for asset in snapshot['assets']: asset['exposure_probability'] = 1
    for finding in snapshot['findings']: finding['scenario_ids'] = []
    for asset in removed['assets']: asset['exposure_probability'] = 1
    assert engine.run(removed, {'calculate_drivers':False})['org']['eal'] == engine.run(snapshot, {'calculate_drivers':False})['org']['eal']


@pytest.mark.parametrize('action', [ {'type':'unknown'}, {'type':'patch_finding','target_id':'missing'},
    {'type':'increase_control_coverage','target_id':'CTRL-MFA-01','coverage_pct':101}])
def test_invalid_actions_rejected(snapshot, action):
    with pytest.raises(ValueError): apply_actions(snapshot, [action])


def test_model_inputs_change_results_and_metadata(snapshot):
    engine = FAIREngine(trials=2000)
    baseline = engine.run(snapshot, {'calculate_drivers':False})
    snapshot['model_assumptions'] = {'loss_multiplier':2}
    changed = engine.run(snapshot, {'calculate_drivers':False})
    assert changed['org']['eal'] > baseline['org']['eal']
    assert changed['snapshot_hash'] != baseline['snapshot_hash']
    assert changed['run_id'] != baseline['run_id']
    assert changed['explanation']['parameter_uncertainty']['calibrated'] is False
    assert sum(changed['loss_breakdown'].values()) == pytest.approx(changed['org']['eal'], abs=.1)


def test_service_results_preserve_configured_recovery_objective(snapshot):
    snapshot['services'][0]['rto_hours'] = 8.0
    result = FAIREngine(trials=1000).run(snapshot, {'calculate_drivers': False})
    service_id = snapshot['services'][0]['id']
    service = next(s for s in result['services'] if s['service_id'] == service_id)
    assert service['rto_hours'] == 8.0


def test_shared_variation_changes_tail_without_changing_expected_intensity(snapshot):
    engine = FAIREngine(trials=20000)
    snapshot['assets'] = snapshot['assets'][:10]
    for asset in snapshot['assets']:
        asset.update(records_count=0, exposure_probability=1, criticality_1_5=3)
    snapshot['services'] = []
    snapshot['controls_catalog'] = []
    snapshot['findings'] = []
    snapshot['assessment_state'] = {'status':'completed'}
    snapshot['scenarios'] = [{'id':'test', 'tef_params':{'low':10,'likely':10,'high':10}}]
    snapshot['model_assumptions'] = {'systemic_sigma':0,'background_probability':.1,
                                   'incident_response':{'low':100,'likely':100,'high':100}}
    independent=engine.run(snapshot,{'calculate_drivers':False})
    snapshot['model_assumptions']['systemic_sigma']=1
    shared=engine.run(snapshot,{'calculate_drivers':False})
    assert shared['org']['eal'] == pytest.approx(independent['org']['eal'],rel=.08)
    assert shared['org']['var99'] > independent['org']['var99'] * 1.5
