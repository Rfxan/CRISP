import test from 'node:test';
import assert from 'node:assert/strict';
import { request, ApiError } from '../src/services/api.js';

test('browser requests serialize calculations and recover after rejection', async () => {
  let active = 0, peak = 0;
  const original = globalThis.fetch;
  globalThis.fetch = async url => {
    active++; peak = Math.max(peak, active);
    await new Promise(resolve => setTimeout(resolve, 15));
    active--;
    return new Response(JSON.stringify(url === '/invalid' ? {detail: 'Unknown control target'} : {ok: true}), {status: url === '/invalid' ? 422 : 200});
  };
  try {
    const results = await Promise.allSettled([request('/first'), request('/invalid'), request('/last')]);
    assert.equal(peak, 1);
    assert.equal(results[0].status, 'fulfilled');
    assert.equal(results[1].reason.status, 422);
    assert.equal(results[1].reason.message, 'Unknown control target');
    assert.equal(results[2].status, 'fulfilled');
  } finally { globalThis.fetch = original; }
});

test('busy responses honor retry headers and retry only a bounded number of times', async () => {
  let calls = 0;
  const original = globalThis.fetch;
  globalThis.fetch = async () => { calls++; return new Response('{"detail":"Calculations busy; retry shortly"}', {status:503, headers:{'Retry-After':'0'}}); };
  try {
    await assert.rejects(request('/busy'), error => error instanceof ApiError && error.status === 503 && error.message.includes('busy'));
    assert.equal(calls, 3);
  } finally { globalThis.fetch = original; }
});

test('validation details retain safe field names and values are never echoed', async () => {
  const original = globalThis.fetch;
  globalThis.fetch = async () => new Response(JSON.stringify({detail:[{loc:['body','budget'],msg:'Must be positive',type:'greater_than'}]}),{status:422});
  try { await assert.rejects(request('/budget'), {message:'budget: Must be positive',status:422}); }
  finally { globalThis.fetch = original; }
});

test('duplicate effect requests share a calculation and retain independent response bodies', async () => {
  const original = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = async () => { calls++; await new Promise(resolve => setTimeout(resolve, 10)); return new Response('{"eal":12}'); };
  try {
    const [first, second] = await Promise.all([request('/api/optimize',{method:'POST',body:'{"budget":100}'}),request('/api/optimize',{method:'POST',body:'{"budget":100}'})]);
    assert.equal(calls, 1);
    assert.deepEqual(await first.json(), {eal:12});
    assert.deepEqual(await second.json(), {eal:12});
  } finally { globalThis.fetch = original; }
});
