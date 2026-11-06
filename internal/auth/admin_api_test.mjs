import assert from 'node:assert/strict';
import {test} from 'node:test';
import {adminApi} from './admin/api.mjs';

test('reviewer client sends the exact version and never reuses a signed-out token', async () => {
  const requests = [];
  const api = adminApi(async (url, options) => {
    requests.push({url, ...options});
    if (url.endsWith('/login')) return Response.json({access_token: 'reviewer', refresh_token: 'ignored'});
    if (url.endsWith('/logout')) return new Response(null, {status: 204});
    if (url.endsWith('/document')) return Response.json({mime: 'image/png', data: 'AA=='});
    return Response.json({submissions: []});
  });
  const target = {kind: 'vehicle', user_id: 7, vehicle_id: 8, version: 9};
  await api.login('+923001234567', 'test password');
  await api.document(target, 'insurance');
  await api.decision(target, 'rejected', 'Replace the image');
  await api.logout();
  await api.queue();
  assert.equal(requests[1].headers.Authorization, 'Bearer reviewer');
  assert.deepEqual(JSON.parse(requests[2].body), {...target, side: 'insurance'});
  assert.deepEqual(JSON.parse(requests[3].body), {...target, decision: 'rejected', reason: 'Replace the image'});
  assert.equal(requests[2].cache, 'no-store');
  assert.equal(requests[4].headers.Authorization, 'Bearer reviewer');
  assert.equal(requests[5].headers.Authorization, undefined);
});

test('a successful sign-in still requires reviewer authorization', async () => {
  const paths = [];
  const api = adminApi(async (path) => {
    paths.push(path);
    if (path.endsWith('/login')) return Response.json({access_token: 'rider'});
    if (path.endsWith('/logout')) return new Response(null, {status: 204});
    return Response.json({error: 'reviewer_required'}, {status: 403});
  });
  await assert.rejects(api.login('+923001234567', 'test password'), {status: 403});
  assert.deepEqual(paths, ['/api/v1/auth/login', '/api/v1/admin/onboarding', '/api/v1/auth/logout']);
});
