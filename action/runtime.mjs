import { appendFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';

const escape = value => String(value).replaceAll('%', '%25').replaceAll('\r', '%0D').replaceAll('\n', '%0A');
export function mask(value) { console.log(`::add-mask::${escape(value)}`); }
export function fail(error) { console.log(`::error::${escape(error.message)}`); process.exitCode = 1; }
function write(file, name, value) {
  if (!file) throw new Error('GitHub Actions environment file is missing');
  const delimiter = `gsts_${randomUUID()}`;
  appendFileSync(file, `${name}<<${delimiter}\n${value}\n${delimiter}\n`, { encoding: 'utf8' });
}
export function endpoint(value, label) {
  let url;
  try { url = new URL(value); } catch { throw new Error(`${label} must be an HTTPS URL`); }
  if (url.protocol !== 'https:' || url.username || url.password || url.hash || url.search) {
    throw new Error(`${label} must be an HTTPS URL without credentials, query, or fragment`);
  }
  return url;
}
function input(env, name) { return (env[`INPUT_${name.toUpperCase()}`] || '').trim(); }
export function config(env) {
  const service = endpoint(input(env, 'service-url'), 'service-url');
  const github = endpoint(input(env, 'github-api-url') || 'https://api.github.com', 'github-api-url');
  const scope = input(env, 'scope'), identity = input(env, 'identity');
  if (!/^[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)?$/.test(scope)) throw new Error('scope must be organization or organization/repository');
  if (!/^[A-Za-z0-9_-][A-Za-z0-9_.-]*$/.test(identity) || identity.includes('..')) throw new Error('identity must be a safe policy filename');
  const body = { scope, identity };
  for (const name of ['permissions', 'repositories']) {
    const raw = input(env, name);
    if (!raw) continue;
    let value;
    try { value = JSON.parse(raw); } catch { throw new Error(`${name} must be valid JSON`); }
    if (name === 'permissions' && (!value || Array.isArray(value) || typeof value !== 'object' || !Object.keys(value).length || !Object.entries(value).every(([k,v]) => /^[a-z_]+$/.test(k) && ['read','write'].includes(v)))) throw new Error('permissions must be a nonempty JSON object of read/write levels');
    if (name === 'repositories' && (scope.includes('/') || !Array.isArray(value) || !value.length || value.length > 500 || !value.every(v => typeof v === 'string' && /^[A-Za-z0-9_.-]+$/.test(v)))) throw new Error('repositories must be a nonempty JSON array for organization scope');
    body[name] = value;
  }
  if (Buffer.byteLength(JSON.stringify(body)) > 16384) throw new Error('Request exceeds 16 KiB');
  service.pathname = `${service.pathname.replace(/\/$/, '')}/token`;
  github.pathname = `${github.pathname.replace(/\/$/, '')}/installation/token`;
  return { service, github, audience: input(env, 'audience') || input(env, 'service-url'), body };
}
export async function request(url, options, fetcher = fetch) {
  try {
    return await fetcher(url, { ...options, redirect: 'error', signal: AbortSignal.timeout(30000) });
  } catch { throw new Error('HTTP request failed (network, timeout, or redirect); request was not retried'); }
}
async function json(response, label) {
  if (!response.ok) { await response.body?.cancel(); throw new Error(`${label} failed (HTTP ${response.status})`); }
  // Limit response consumption, including chunked responses.
  const reader = response.body?.getReader();
  if (!reader) throw new Error(`${label} returned an empty response`);
  let length = 0; const chunks = [];
  try {
    for (;;) { const { done, value } = await reader.read(); if (done) break; length += value.length; if (length > 65536) throw new Error(`${label} response exceeds 64 KiB`); chunks.push(value); }
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch { throw new Error(`${label} returned an invalid or oversized response`); }
  finally { await reader.cancel().catch(() => {}); }
}
export async function main(env = process.env, fetcher = fetch) {
  const cfg = config(env);
  if (!env.ACTIONS_ID_TOKEN_REQUEST_URL || !env.ACTIONS_ID_TOKEN_REQUEST_TOKEN) throw new Error('OIDC is unavailable; grant this job id-token: write');
  let oidcURL;
  try { oidcURL = new URL(env.ACTIONS_ID_TOKEN_REQUEST_URL); } catch { throw new Error('Invalid runner OIDC URL'); }
  if (oidcURL.protocol !== 'https:' || oidcURL.username || oidcURL.password || oidcURL.hash) throw new Error('Invalid runner OIDC URL');
  oidcURL.searchParams.set('audience', cfg.audience);
  mask(env.ACTIONS_ID_TOKEN_REQUEST_TOKEN);
  const oidc = await json(await request(oidcURL, { headers: { Authorization: `Bearer ${env.ACTIONS_ID_TOKEN_REQUEST_TOKEN}` } }, fetcher), 'OIDC request');
  if (!oidc || typeof oidc !== 'object' || Array.isArray(oidc) || typeof oidc.value !== 'string' || !oidc.value || /\s/.test(oidc.value)) throw new Error('OIDC response has no valid token');
  mask(oidc.value);
  const result = await json(await request(cfg.service, { method: 'POST', headers: { Authorization: `Bearer ${oidc.value}`, 'Content-Type': 'application/json' }, body: JSON.stringify(cfg.body) }, fetcher), 'gsts exchange');
  if (!result || typeof result !== 'object' || Array.isArray(result) || typeof result.token !== 'string' || !result.token || /\s/.test(result.token)) throw new Error('gsts response has no valid token');
  mask(result.token);
  // Persist cleanup before publishing any output, even if later response validation fails.
  try {
    write(env.GITHUB_STATE, 'revoke-url', cfg.github.href);
    write(env.GITHUB_STATE, 'token', result.token);
  } catch {
    try { await post({ STATE_token: result.token, 'STATE_revoke-url': cfg.github.href }, fetcher); }
    catch { throw new Error('Could not save cleanup state, and immediate token revocation failed'); }
    throw new Error('Could not save cleanup state; token revoked immediately');
  }
  if (typeof result.expires_at !== 'string' || !Number.isFinite(Date.parse(result.expires_at))) throw new Error('gsts response has no valid expiration');
  write(env.GITHUB_OUTPUT, 'token', result.token);
  write(env.GITHUB_OUTPUT, 'expires-at', result.expires_at);
}
export async function post(env = process.env, fetcher = fetch) {
  const token = env.STATE_token;
  if (!token) return;
  mask(token);
  const url = endpoint(env['STATE_revoke-url'], 'saved GitHub API URL');
  const response = await request(url, { method: 'DELETE', headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' } }, fetcher);
  await response.body?.cancel();
  if (response.status !== 204 && response.status !== 401) throw new Error(`Token revocation failed (HTTP ${response.status})`);
  console.log(response.status === 204 ? 'gsts installation token revoked.' : 'gsts installation token is already invalid.');
}
