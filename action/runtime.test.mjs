import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { config, endpoint, main, mask, post, request } from './runtime.mjs';
function env() { const dir = mkdtempSync(join(tmpdir(), 'gsts-action-')); return { 'INPUT_SERVICE-URL': 'https://gsts.example', INPUT_SCOPE: 'org/repo', INPUT_IDENTITY: 'deploy', ACTIONS_ID_TOKEN_REQUEST_URL: 'https://oidc.example/token?x=1', ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'runner-secret', GITHUB_STATE: join(dir, 'state'), GITHUB_OUTPUT: join(dir, 'output') }; }
const reply = value => new Response(JSON.stringify(value), {status:200});
test('reject unsafe endpoints and invalid request scope before fetching', () => {
  for (const url of ['http://service.example', 'https://user:secret@example.com', 'https://example.com?q=1', 'https://example.com/#x']) assert.throws(() => endpoint(url, 'endpoint'));
  assert.throws(() => config({...env(), INPUT_SCOPE:'org/repo/extra'}));
  assert.throws(() => config({...env(), INPUT_IDENTITY:'../deploy'}));
  assert.throws(() => config({...env(), INPUT_PERMISSIONS:'{"contents":"admin"}'}));
  assert.throws(() => config({...env(), INPUT_REPOSITORIES:'["repo"]'}));
});
test('OIDC audience, exchange, cleanup state, then outputs', async () => {
  const e = env(); const calls = [];
  await main(e, async (url, opts) => { calls.push({url:new URL(url),opts}); assert.equal(opts.redirect,'error'); return calls.length === 1 ? reply({value:'oidc-secret'}) : reply({token:'installation-secret',expires_at:'2026-10-12T00:00:00Z'}); });
  assert.equal(calls.length,2); assert.equal(calls[0].url.searchParams.get('audience'),'https://gsts.example');
  assert.equal(calls[1].url.href,'https://gsts.example/token');
  assert.equal(calls[1].opts.headers.Authorization,'Bearer oidc-secret');
  assert.deepEqual(JSON.parse(calls[1].opts.body),{scope:'org/repo',identity:'deploy'});
  assert.match(readFileSync(e.GITHUB_STATE,'utf8'),/installation-secret/);
  assert.match(readFileSync(e.GITHUB_OUTPUT,'utf8'),/installation-secret/);
});
test('cleanup is persisted even if expiration validation fails', async () => {
  const e = env(); let n = 0;
  await assert.rejects(main(e, async () => ++n === 1 ? reply({value:'oidc-secret'}) : reply({token:'installation-secret'})), /expiration/);
  assert.match(readFileSync(e.GITHUB_STATE,'utf8'),/installation-secret/);
  assert.throws(() => readFileSync(e.GITHUB_OUTPUT));
});
test('exchange failure is sanitized and never retried', async () => {
  let calls=0;
  await assert.rejects(main(env(), async () => ++calls===1 ? reply({value:'oidc-secret'}) : new Response('private upstream body',{status:403})), /HTTP 403/);
  assert.equal(calls,2);
});
test('network exceptions do not expose secrets', async () => {
  await assert.rejects(request('https://example.com',{},async () => { throw new Error('private-token'); }), error => !error.message.includes('private-token'));
});
test('post revokes with installation token and handles invalid tokens', async () => {
  for (const status of [204,401]) await post({STATE_token:'installation-secret','STATE_revoke-url':'https://api.github.com/installation/token'}, async (url,opts) => {
    assert.equal(url.href,'https://api.github.com/installation/token'); assert.equal(opts.method,'DELETE'); assert.equal(opts.headers.Authorization,'Bearer installation-secret'); assert.equal(opts.redirect,'error'); return new Response(null,{status});
  });
  await assert.rejects(post({STATE_token:'secret','STATE_revoke-url':'https://api.github.com/installation/token'}, async () => new Response(null,{status:500})), /revocation failed/);
  await post({}, () => { throw new Error('should not fetch'); });
});
test('state file failure triggers immediate revocation without output', async () => {
  const e = env(); e.GITHUB_STATE = '/dev/null/no-state'; let calls=0;
  await assert.rejects(main(e, async (url,opts) => {
    calls++;
    if(calls===1) return reply({value:'oidc-secret'});
    if(calls===2) return reply({token:'installation-secret',expires_at:'2026-10-12T00:00:00Z'});
    assert.equal(opts.method,'DELETE'); return new Response(null,{status:204});
  }), /revoked immediately/);
  assert.equal(calls,3); assert.throws(() => readFileSync(e.GITHUB_OUTPUT));
});
test('oversized responses fail without publishing outputs', async () => {
  const e=env();
  await assert.rejects(main(e, async () => new Response('x'.repeat(65537))), /oversized/);
  assert.throws(() => readFileSync(e.GITHUB_OUTPUT));
});
test('null or array JSON responses produce curated errors', async () => {
  for (const malformed of [null, []]) {
    const e=env();
    await assert.rejects(main(e, async () => reply(malformed)), /OIDC response has no valid token/);
    assert.throws(() => readFileSync(e.GITHUB_OUTPUT));
    let calls=0;
    await assert.rejects(main(e, async () => ++calls === 1 ? reply({value:'oidc-secret'}) : reply(malformed)), /gsts response has no valid token/);
    assert.throws(() => readFileSync(e.GITHUB_STATE));
    assert.throws(() => readFileSync(e.GITHUB_OUTPUT));
  }
});

test('mask commands escape percent and line breaks', () => {
  const original=console.log; const lines=[];
  console.log=value => lines.push(value);
  try { mask('secret%\r\n::error::injected'); } finally { console.log=original; }
  assert.deepEqual(lines,['::add-mask::secret%25%0D%0A::error::injected']);
});
