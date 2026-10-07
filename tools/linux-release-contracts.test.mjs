import assert from 'node:assert/strict'
import { createPrivateKey, createPublicKey, randomBytes, verify } from 'node:crypto'
import { mkdir, mkdtemp, readFile, readlink, realpath, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import test from 'node:test'

import { RELEASE_REPOSITORY, fileSha256, releaseIdentity } from './release-evidence-lib.mjs'
import { assertCandidateArtifactsBindAssets, LINUX_RELEASE_KIND, LINUX_RELEASE_WORKFLOW, validateLinuxEvidenceDirectory, validateLinuxHandoffPackageBytes, validateLinuxReleaseManifest, validateLinuxSigstoreEvidence } from './linux-release-evidence.mjs'
import { buildLinuxCandidate } from './create-linux-release-candidate.mjs'
import { releaseSetSigningPayload, verifyReleaseSet } from './release-set.mjs'
import { addHelperAlias, appRunHookWithLibraryPath, patchSandboxPaths, planStrippedLibraries, webkitHelperAlias } from './strip-appimage-host-libs.mjs'

const version = '1.2.3'
const architecture = 'x86_64'
const ref = `refs/tags/v${version}`
const identity = releaseIdentity(RELEASE_REPOSITORY, LINUX_RELEASE_WORKFLOW, ref)

async function evidenceFixture({ omitFormat } = {}) {
  const root = await mkdtemp(path.join(tmpdir(), 'sesame-linux-release-'))
  const manifestFilename = `sesame-${version}-linux-${architecture}.release.json`
  const packages = [
    { format: 'appimage', filename: `Sesame-${version}-${architecture}.AppImage`, bytes: 'fictional appimage package' },
    { format: 'deb', filename: `Sesame_${version}_amd64.deb`, bytes: 'fictional deb package' },
    { format: 'rpm', filename: `Sesame-${version}-1.${architecture}.rpm`, bytes: 'fictional rpm package' },
  ].filter((entry) => entry.format !== omitFormat)
  const artifacts = []
  for (const entry of packages) {
    const location = path.join(root, entry.filename)
    await writeFile(location, entry.bytes)
    await writeFile(`${location}.sigstore.json`, `{"fictional":"${entry.format} bundle"}`)
    artifacts.push({ format: entry.format, filename: entry.filename, sha256: await fileSha256(location), bytes: entry.bytes.length })
  }
  for (const [label, content] of [
    ['sbom', '{"bomFormat":"CycloneDX"}\n'],
    ['shipped', '{"schema":"sesame.linux-shipped-package-run/1"}\n'],
    ['rpm', '{"schema":"sesame.linux-rpm-shipped-package-run/1"}\n'],
    ['appimage', '{"schema":"sesame.linux-appimage-shipped-package-run/1"}\n'],
    ['vault', '{"schema":"sesame.linux-installed-package-run/1"}\n'],
  ]) {
    await writeFile(path.join(root, `${label}.json`), content)
  }
  const manifest = {
    schemaVersion: 1,
    product: 'Sesame',
    releaseKind: LINUX_RELEASE_KIND,
    version,
    channel: 'beta',
    platform: 'linux',
    architecture,
    source: { repository: RELEASE_REPOSITORY, workflow: LINUX_RELEASE_WORKFLOW, ref, commit: 'a'.repeat(40) },
    artifacts,
    sbom: { filename: 'sbom.json', sha256: await fileSha256(path.join(root, 'sbom.json')), bytes: (await readFile(path.join(root, 'sbom.json'))).length },
    linuxLifecycle: {
      shipped: { filename: 'shipped.json', sha256: await fileSha256(path.join(root, 'shipped.json')), bytes: (await readFile(path.join(root, 'shipped.json'))).length },
      rpm: { filename: 'rpm.json', sha256: await fileSha256(path.join(root, 'rpm.json')), bytes: (await readFile(path.join(root, 'rpm.json'))).length },
      appimage: { filename: 'appimage.json', sha256: await fileSha256(path.join(root, 'appimage.json')), bytes: (await readFile(path.join(root, 'appimage.json'))).length },
      vault: { filename: 'vault.json', sha256: await fileSha256(path.join(root, 'vault.json')), bytes: (await readFile(path.join(root, 'vault.json'))).length },
    },
    sigstore: { issuer: 'https://token.actions.githubusercontent.com', certificateIdentity: identity, transparencyLogRequired: true },
    releaseNotesUrl: `https://github.com/${RELEASE_REPOSITORY}/releases/tag/v${version}`,
  }
  await writeFile(path.join(root, manifestFilename), `${JSON.stringify(manifest, null, 2)}\n`)
  const manifestBundle = `${manifestFilename}.sigstore.json`
  await writeFile(path.join(root, manifestBundle), '{"fictional":"manifest bundle"}\n')
  const evidence = {
    schemaVersion: 1,
    verified: true,
    transparencyLogVerified: true,
    issuer: manifest.sigstore.issuer,
    certificateIdentity: identity,
    repository: RELEASE_REPOSITORY,
    workflow: LINUX_RELEASE_WORKFLOW,
    ref,
    sourceCommit: manifest.source.commit,
    manifestSha256: await fileSha256(path.join(root, manifestFilename)),
    manifestBundleSha256: await fileSha256(path.join(root, manifestBundle)),
    artifacts: await Promise.all(artifacts.map(async (artifact) => ({ filename: artifact.filename, sha256: artifact.sha256, bundleSha256: await fileSha256(path.join(root, `${artifact.filename}.sigstore.json`)) }))),
    verifiedAt: '2026-09-13T00:00:00.000Z',
  }
  await writeFile(path.join(root, 'linux-sigstore-evidence.json'), `${JSON.stringify(evidence, null, 2)}\n`)
  return { root, manifest, manifestFilename, evidence, artifacts }
}

test('the Linux release manifest carries exactly the three packages and all four lifecycle records', async () => {
  const value = await evidenceFixture()
  try {
    const manifest = validateLinuxReleaseManifest(value.manifest)
    assert.deepEqual(manifest.artifacts.map((artifact) => artifact.format).sort(), ['appimage', 'deb', 'rpm'])
    assert.throws(() => validateLinuxReleaseManifest({ ...value.manifest, releaseKind: 'unsigned-windows-early-access' }), /identity is invalid/)
    assert.throws(() => validateLinuxReleaseManifest({ ...value.manifest, source: { ...value.manifest.source, workflow: '.github/workflows/other.yml' } }), /protected Sesame tag workflow/)
    const missingFormat = structuredClone(value.manifest)
    missingFormat.artifacts = missingFormat.artifacts.filter((artifact) => artifact.format !== 'rpm')
    assert.throws(() => validateLinuxReleaseManifest(missingFormat), /exactly the appimage, deb, rpm packages/)
    const missingLifecycle = structuredClone(value.manifest)
    delete missingLifecycle.linuxLifecycle.vault
    assert.throws(() => validateLinuxReleaseManifest(missingLifecycle), /vault filename must be a plain release filename/)
  } finally { await rm(value.root, { recursive: true, force: true }) }
})

test('the Linux evidence directory binds every package, bundle, and record', async () => {
  const value = await evidenceFixture()
  try {
    const { manifest } = await validateLinuxEvidenceDirectory(value.root, value.manifestFilename)
    assert.equal(manifest.version, version)
    await writeFile(path.join(value.root, value.artifacts[1].filename), 'swapped package bytes')
    await assert.rejects(validateLinuxEvidenceDirectory(value.root, value.manifestFilename), /does not match the signed Linux release manifest/)
  } finally { await rm(value.root, { recursive: true, force: true }) }
  const bundle = await evidenceFixture()
  try {
    await writeFile(path.join(bundle.root, `${bundle.artifacts[0].filename}.sigstore.json`), '{"substituted":true}')
    await assert.rejects(validateLinuxEvidenceDirectory(bundle.root, bundle.manifestFilename), /Sigstore bundle was substituted/)
  } finally { await rm(bundle.root, { recursive: true, force: true }) }
})

test('the Linux handoff verifier checks downloaded bytes against the frozen manifest', async () => {
  const value = await evidenceFixture()
  try {
    const manifest = await validateLinuxHandoffPackageBytes(value.root, value.manifestFilename)
    assert.deepEqual(manifest.artifacts.map((artifact) => artifact.filename).sort(), value.artifacts.map((artifact) => artifact.filename).sort())
    await writeFile(path.join(value.root, value.artifacts[1].filename), 'swapped package bytes')
    await assert.rejects(validateLinuxHandoffPackageBytes(value.root, value.manifestFilename), /does not match the frozen release manifest/)
  } finally { await rm(value.root, { recursive: true, force: true }) }
  const counts = await evidenceFixture()
  try {
    const manifest = structuredClone(counts.manifest)
    manifest.artifacts[0].bytes += 1
    await writeFile(path.join(counts.root, counts.manifestFilename), `${JSON.stringify(manifest, null, 2)}\n`)
    await assert.rejects(validateLinuxHandoffPackageBytes(counts.root, counts.manifestFilename), /does not match the frozen release manifest/)
  } finally { await rm(counts.root, { recursive: true, force: true }) }
})

test('the Linux sigstore record must verify every package', async () => {
  const value = await evidenceFixture()
  try {
    const incomplete = structuredClone(value.evidence)
    incomplete.artifacts = incomplete.artifacts.slice(0, 2)
    assert.throws(() => validateLinuxSigstoreEvidence(incomplete, value.manifest), /does not cover every package/)
    const mismatched = structuredClone(value.evidence)
    mismatched.artifacts[0].sha256 = 'f'.repeat(64)
    assert.throws(() => validateLinuxSigstoreEvidence(mismatched, value.manifest), /does not verify/)
  } finally { await rm(value.root, { recursive: true, force: true }) }
})

test('the Linux candidate is a signed release set with no updater artifact', async () => {
  const value = await evidenceFixture()
  try {
    const seed = randomBytes(32)
    const pkcs8 = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed])
    const privateKey = createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' })
    const candidate = buildLinuxCandidate({
      manifest: value.manifest,
      evidence: value.evidence,
      signingKey: seed.toString('base64url'),
      signingKeyId: 'candidate-1',
      assetBase: `https://github.com/${RELEASE_REPOSITORY}/releases/download/v${version}`,
      objectKeyPrefix: `linux/v${version}`,
    })
    verifyReleaseSet(candidate)
    assert.equal(candidate.platform, 'linux')
    assert.equal(candidate.artifacts.length, 3)
    assert.ok(candidate.artifacts.every((artifact) => artifact.updaterCapable === false))
    const deb = candidate.artifacts.find((artifact) => artifact.format === 'deb')
    const debFilename = value.artifacts.find((artifact) => artifact.format === 'deb').filename
    assert.equal(deb.sha256, value.artifacts.find((artifact) => artifact.format === 'deb').sha256)
    assert.equal(deb.url, `https://github.com/${RELEASE_REPOSITORY}/releases/download/v${version}/${debFilename}`)
    assert.equal(verify(null, Buffer.from(releaseSetSigningPayload(candidate)), createPublicKey(privateKey), Buffer.from(candidate.candidateSignature, 'base64url')), true)
  } finally { await rm(value.root, { recursive: true, force: true }) }
})

test('the candidate binds the verified package bytes by its asset URLs', async () => {
  const value = await evidenceFixture()
  try {
    const seed = randomBytes(32)
    const candidate = buildLinuxCandidate({
      manifest: value.manifest,
      evidence: value.evidence,
      signingKey: seed.toString('base64url'),
      signingKeyId: 'candidate-1',
      assetBase: `https://github.com/${RELEASE_REPOSITORY}/releases/download/v${version}`,
      objectKeyPrefix: `linux/v${version}`,
    })
    const assets = value.manifest.artifacts.map((artifact) => ({ name: artifact.filename, sha256: artifact.sha256, bytes: artifact.bytes }))
    assertCandidateArtifactsBindAssets(candidate, assets, { repository: RELEASE_REPOSITORY, tag: `v${version}` })

    const tampered = structuredClone(candidate)
    tampered.artifacts[0] = { ...tampered.artifacts[0], sha256: 'f'.repeat(64) }
    assert.throws(() => assertCandidateArtifactsBindAssets(tampered, assets, { repository: RELEASE_REPOSITORY, tag: `v${version}` }), /does not bind the verified package bytes/)

    const wrongUrl = structuredClone(candidate)
    wrongUrl.artifacts[0] = { ...wrongUrl.artifacts[0], url: wrongUrl.artifacts[0].url.replace(`v${version}`, 'v1.2.2') }
    assert.throws(() => assertCandidateArtifactsBindAssets(wrongUrl, assets, { repository: RELEASE_REPOSITORY, tag: `v${version}` }), /does not bind the verified package bytes/)
  } finally { await rm(value.root, { recursive: true, force: true }) }
})

test('the Linux release workflow publishes only after both installed-package gates', async () => {
  const workflow = await readFile(path.join(process.cwd(), '.github', 'workflows', 'release-linux-early-access.yml'), 'utf8')
  assert.match(workflow, /linux-shipped-package-gate\.mjs/, 'the lane does not run the shipped-package gate')
  assert.match(workflow, /linux-installed-package-gate\.mjs/, 'the lane does not run the installed-package vault gate')
  assert.match(workflow, /prepare-linux-release-evidence\.mjs/, 'the lane does not freeze the Linux release manifest')
  assert.match(workflow, /verify-linux-release-evidence\.mjs/, 'the lane does not independently verify the downloaded evidence')
  const publish = workflow.slice(workflow.indexOf('publish:'))
  assert.match(publish, /needs: \[sign-and-attest, verify-fresh\]/, 'publication does not wait for the gates')
  assert.match(publish, /submit-release-candidate\.mjs/, 'the lane does not submit the server candidate')
  const build = workflow.slice(workflow.indexOf('\n  build-and-test:\n'), workflow.indexOf('\n  sign-and-attest:\n'))
  assert.doesNotMatch(build, /id-token/, 'the Linux build job must not be able to mint an OIDC token')
})

test('the AppImage keeps host-provided Wayland libraries out of the bundle', () => {
  assert.deepEqual(planStrippedLibraries(['libwayland-client.so.0', 'libwayland-cursor.so.0', 'libwayland-egl.so.1', 'libwayland-server.so.0', 'libxkbcommon.so.0', 'libgtk-3.so.0']), ['libwayland-client.so.0', 'libwayland-cursor.so.0'])
})

test('the Linux release lane strips the AppImage before the gates bind its bytes', async () => {
  const workflow = await readFile(path.join(process.cwd(), '.github', 'workflows', 'release-linux-early-access.yml'), 'utf8')
  const strip = workflow.indexOf('strip-appimage-host-libs.mjs')
  assert.ok(strip >= 0, 'the lane does not strip the host-provided Wayland libraries from the AppImage')
  assert.ok(strip < workflow.indexOf('linux-shipped-package-gate.mjs'), 'the lane must strip the AppImage before the package gates run')
  assert.ok(strip < workflow.indexOf('prepare-linux-release-evidence.mjs'), 'the lane must strip the AppImage before the manifest freezes its bytes')
})

test('the Linux release lane prepares the web view sandbox before its package gates', async () => {
  const workflow = await readFile(path.join(process.cwd(), '.github', 'workflows', 'release-linux-early-access.yml'), 'utf8')
  const build = workflow.slice(workflow.indexOf('\n  build-and-test:\n'), workflow.indexOf('\n  sign-and-attest:\n'))
  const userns = build.indexOf('apparmor_restrict_unprivileged_userns')
  assert.match(build, /\n\s+bubblewrap \\\n\s+xdg-dbus-proxy \\\n/, 'the lane does not install bubblewrap and xdg-dbus-proxy')
  assert.ok(userns >= 0, 'the lane does not allow unprivileged user namespaces')
  assert.ok(userns < build.indexOf('linux-shipped-package-gate.mjs'), 'the lane must allow user namespaces before the package gates run')
})

test('the AppImage patch points the WebKit sandbox tools and system directories at the system paths', () => {
  const contents = Buffer.from('a ././/bin/bwrap b ././/bin/xdg-dbus-proxy c ././/lib d ././/lib64 e ././/lib/x86_64-linux-gnu f ././/share g ././/local/share h')
  const result = patchSandboxPaths(contents)
  assert.equal(result.replaced, 7)
  assert.equal(result.contents.length, contents.length)
  assert.ok(!result.contents.includes('././/'))
  for (const system of ['/usr/bin/bwrap', '/usr/bin/xdg-dbus-proxy', '/usr/lib ', '/usr/lib64 ', '/usr/lib/x86_64-linux-gnu ', '/usr/share ', '/usr/local/share ']) {
    assert.ok(result.contents.includes(system), system)
  }
  assert.equal(patchSandboxPaths(result.contents).replaced, 0)
})

test('the AppImage patch keeps the WebKit helper directory relative under its own name', () => {
  const helpers = '././/lib/x86_64-linux-gnu/webkit2gtk-4.1'
  const contents = Buffer.from(`a ${helpers} b ${helpers}/injected-bundle/ c ././/lib/x86_64-linux-gnu d`)
  const result = patchSandboxPaths(contents)
  const patched = result.contents.toString()
  assert.equal(result.contents.length, contents.length)
  assert.ok(patched.includes(`./${webkitHelperAlias}/lib/x86_64-linux-gnu/webkit2gtk-4.1 `))
  assert.ok(patched.includes(`./${webkitHelperAlias}/lib/x86_64-linux-gnu/webkit2gtk-4.1/injected-bundle/`))
  assert.ok(patched.includes(' /usr/lib/x86_64-linux-gnu d'))
  assert.ok(!patched.includes('././/'))
})

test('the AppImage gets a helper alias that points at its usr directory once', async () => {
  const tree = await mkdtemp(path.join(tmpdir(), 'alias-test-'))
  try {
    await mkdir(path.join(tree, 'usr', 'lib', 'x86_64-linux-gnu'), { recursive: true })
    assert.equal(await addHelperAlias(tree), true)
    assert.equal(await addHelperAlias(tree), false)
    assert.equal(await readlink(path.join(tree, 'usr', webkitHelperAlias)), '.')
    assert.equal(
      await realpath(path.join(tree, 'usr', webkitHelperAlias, 'lib', 'x86_64-linux-gnu')),
      await realpath(path.join(tree, 'usr', 'lib', 'x86_64-linux-gnu')),
    )
  } finally {
    await rm(tree, { recursive: true, force: true })
  }
})

test('the sandbox path patch refuses a replacement with a different length', () => {
  assert.throws(() => patchSandboxPaths(Buffer.from('abc'), [['abc', 'abcd']]), /byte length/)
})

test('the AppRun hook gains the bundled usr library path once', () => {
  const hook = '#!/bin/sh\nexport APPDIR="${APPDIR:-$(dirname "$0")}"\n'
  const patched = appRunHookWithLibraryPath(hook)
  assert.ok(patched.includes('export LD_LIBRARY_PATH="$APPDIR/usr${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"'))
  assert.ok(patched.startsWith(hook))
  assert.equal(appRunHookWithLibraryPath(patched), null)
})

test('the Linux CI patches the AppImage before the AppImage gate binds it', async () => {
  const workflow = await readFile(path.join(process.cwd(), '.github', 'workflows', 'ci.yml'), 'utf8')
  const patch = workflow.indexOf('strip-appimage-host-libs.mjs')
  assert.ok(patch >= 0, 'the desktop-linux job does not patch the AppImage sandbox paths')
  assert.ok(patch < workflow.indexOf('--format appimage'), 'the job must patch the AppImage before its gate runs')
})
