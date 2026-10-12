import assert from 'node:assert/strict'
import { existsSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

import {
  countAnonymousExecutableMappings,
  judge,
  judgeWebProcess,
  parseEnvironment,
  parseStatus,
} from './linux-webview-sandbox-check.mjs'

const root = dirname(dirname(fileURLToPath(import.meta.url)))
const read = (...parts) => readFileSync(join(root, ...parts), 'utf8')

const host = { mnt: 'mnt:[1]', pid: 'pid:[2]', user: 'user:[3]', net: 'net:[4]' }
const sandboxed = (pid = 100) => ({
  pid,
  status: { Seccomp: '2', NoNewPrivs: '1' },
  namespaces: { mnt: 'mnt:[11]', pid: 'pid:[12]', user: 'user:[13]', net: 'net:[14]' },
  environment: { JSC_useJIT: '0' },
  anonymousExecutableMappings: 0,
})

test('a sandboxed web process with the JIT off passes', () => {
  assert.deepEqual(judgeWebProcess(sandboxed(), host), [])
  assert.deepEqual(judge({ webProcesses: [sandboxed(1), sandboxed(2)], host, logText: '' }), { state: 'sandboxed', failures: [] })
})

test('a web process without seccomp, no_new_privs or its own namespaces fails', () => {
  assert.equal(judgeWebProcess({ ...sandboxed(), status: { Seccomp: '0', NoNewPrivs: '1' } }, host).length, 1)
  assert.equal(judgeWebProcess({ ...sandboxed(), status: { Seccomp: '2', NoNewPrivs: '0' } }, host).length, 1)
  for (const name of ['mnt', 'pid', 'user', 'net']) {
    const shared = { ...sandboxed(), namespaces: { ...sandboxed().namespaces, [name]: host[name] } }
    assert.match(judgeWebProcess(shared, host).join('\n'), new RegExp(`shares the ${name} namespace`))
  }
})

test('unreadable state fails closed', () => {
  const unreadable = { pid: 7, status: null, namespaces: {}, environment: null, anonymousExecutableMappings: null }
  assert.equal(judgeWebProcess(unreadable, host).length, 8)
  assert.equal(judge({ webProcesses: [unreadable], host, logText: '' }).state, 'unsandboxed')
})

test('one unsandboxed renderer among sandboxed ones fails the run', () => {
  const loose = { ...sandboxed(2), status: { Seccomp: '0', NoNewPrivs: '0' } }
  const result = judge({ webProcesses: [sandboxed(1), loose], host, logText: '' })
  assert.equal(result.state, 'unsandboxed')
  assert.equal(result.failures.length, 2)
})

test('a JIT that is on or an executable anonymous mapping fails', () => {
  assert.match(judgeWebProcess({ ...sandboxed(), environment: { JSC_useJIT: '1' } }, host).join('\n'), /JSC_useJIT 1/)
  assert.match(judgeWebProcess({ ...sandboxed(), environment: {} }, host).join('\n'), /JSC_useJIT unreadable/)
  assert.match(judgeWebProcess({ ...sandboxed(), anonymousExecutableMappings: 3 }, host).join('\n'), /3 anonymous executable mappings/)
})

test('no web process is a refusal only when the app says so', () => {
  assert.equal(judge({ webProcesses: [], host, logText: 'Sesame did not start because the sandbox for its web view is not available. x' }).state, 'refused')
  assert.equal(judge({ webProcesses: [], host, logText: '' }).state, 'no_renderer')
})

test('proc files are parsed without trusting their shape', () => {
  assert.deepEqual(parseStatus('Name:\tWebKitWebProces\nSeccomp:\t2\nNoNewPrivs:\t1\nbroken line\n'), { Name: 'WebKitWebProces', Seccomp: '2', NoNewPrivs: '1' })
  assert.deepEqual(parseEnvironment('A=1\0JSC_useJIT=0\0=bad\0novalue\0'), { A: '1', JSC_useJIT: '0' })
  const maps = [
    '7f00-7f10 rwxp 00000000 00:00 0 ',
    '7f20-7f30 r-xp 00000000 08:01 12 /usr/lib/libc.so.6',
    '7f40-7f50 r-xp 00000000 00:00 0',
    '7f60-7f70 rw-p 00000000 00:00 0',
  ].join('\n')
  assert.equal(countAnonymousExecutableMappings(maps), 2)
})

test('the sandbox and the JIT switch are set after the launch scrub and before the builder', () => {
  const rust = read('src-tauri', 'src', 'lib.rs')
  const run = rust.indexOf('pub fn run()')
  const scrub = rust.indexOf('prepare_release_webview_environment();', run)
  const sandbox = rust.indexOf('webview_sandbox::prepare()', run)
  const context = rust.indexOf('tauri::generate_context!()', run)
  const refusal = rust.indexOf('webview_sandbox::refuse(', run)
  const builder = rust.indexOf('tauri::Builder::default()', run)
  assert.ok(run >= 0 && scrub > run, 'the launch scrub runs in run()')
  assert.ok(sandbox > scrub, 'the sandbox preparation follows the scrub')
  assert.ok(context > sandbox && refusal > sandbox, 'the refusal depends on the preparation result')
  assert.ok(builder > refusal, 'the refusal returns before the app builder runs')
  assert.match(rust.slice(refusal, builder), /return;/)
})

test('the sandbox module forces the sandbox, switches the JIT off and removes the disable variable', () => {
  const source = read('src-tauri', 'src', 'adapters', 'platform', 'webview_sandbox.rs').split('#[cfg(test)]')[0]
  assert.match(source, /REMOVED_VARIABLES: \[&str; 1\] = \["WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS"\]/)
  assert.match(source, /\("WEBKIT_FORCE_SANDBOX", "1"\)/)
  assert.match(source, /\("JSC_useJIT", "0"\)/)
  assert.match(source, /"\/usr\/bin\/bwrap"/)
  assert.match(source, /"\/usr\/bin\/xdg-dbus-proxy"/)
})

test('no scrub list removes the sandbox or JIT variables that the sandbox module sets', () => {
  const scrub = join(root, 'src-tauri', 'src', 'adapters', 'platform', 'webview_environment.rs')
  if (!existsSync(scrub)) return
  const source = readFileSync(scrub, 'utf8').split('#[cfg(test)]')[0]
  assert.doesNotMatch(source, /"WEBKIT_FORCE_SANDBOX"/)
  assert.doesNotMatch(source, /"JSC_useJIT"/)
})

test('the deb and rpm depend on bubblewrap and xdg-dbus-proxy', () => {
  const config = JSON.parse(read('src-tauri', 'tauri.conf.json'))
  for (const format of ['deb', 'rpm']) {
    assert.deepEqual(config.bundle.linux[format].depends, ['bubblewrap', 'xdg-dbus-proxy'], format)
  }
})

test('the runtime check is reachable from package.json', () => {
  const scripts = JSON.parse(read('package.json')).scripts
  assert.match(scripts['desktop:linux:webview:check'], /tools\/linux-webview-sandbox-check\.mjs/)
})
