import assert from 'node:assert/strict'
import { createPrivateKey, createPublicKey, randomBytes, verify } from 'node:crypto'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import test from 'node:test'

import { RELEASE_REPOSITORY, fileSha256, releaseIdentity } from './release-evidence-lib.mjs'
import { assertCandidateArtifactsBindAssets, LINUX_RELEASE_KIND, LINUX_RELEASE_WORKFLOW, validateLinuxEvidenceDirectory, validateLinuxReleaseManifest, validateLinuxSigstoreEvidence } from './linux-release-evidence.mjs'
import { buildLinuxCandidate } from './create-linux-release-candidate.mjs'
import { releaseSetSigningPayload, verifyReleaseSet } from './release-set.mjs'

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

test('the Linux release manifest carries exactly the three packages and both lifecycle records', async () => {
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
  assert.match(publish, /needs: \[build-and-test, verify-fresh\]/, 'publication does not wait for the gates')
  assert.match(publish, /submit-release-candidate\.mjs/, 'the lane does not submit the server candidate')
})
