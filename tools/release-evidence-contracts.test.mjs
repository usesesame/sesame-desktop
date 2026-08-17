import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import test from 'node:test'
import { promisify } from 'node:util'

import { RELEASE_REPOSITORY, RELEASE_WORKFLOW, SIGSTORE_ISSUER, fileSha256, releaseIdentity, validateEvidenceDirectory, validateReleaseManifest } from './release-evidence-lib.mjs'

const run = promisify(execFile)

async function fixture() {
  const root = await mkdtemp(path.join(tmpdir(), 'sesame-release-evidence-'))
  const version = '1.2.3'
  const ref = `refs/tags/v${version}`
  const files = {
    artifact: 'Sesame_1.2.3_x64-setup.exe',
    updaterSignature: 'Sesame_1.2.3_x64-setup.exe.sig',
    sbom: 'sesame-1.2.3.cdx.json',
    manifest: 'sesame-1.2.3-windows-x86_64.release.json',
  }
  await writeFile(path.join(root, files.artifact), 'fictional installer bytes')
  await writeFile(path.join(root, files.updaterSignature), 'A'.repeat(64))
  await writeFile(path.join(root, files.sbom), '{"bomFormat":"CycloneDX"}\n')
  const describe = async (filename) => ({ filename, sha256: await fileSha256(path.join(root, filename)), bytes: (await readFile(path.join(root, filename))).length })
  const manifest = {
    schemaVersion: 1, product: 'Sesame', releaseKind: 'unsigned-windows-early-access', version, channel: 'beta', platform: 'windows', architecture: 'x86_64',
    source: { repository: RELEASE_REPOSITORY, workflow: RELEASE_WORKFLOW, ref, commit: 'a'.repeat(40) },
    artifact: await describe(files.artifact),
    updaterSignature: { ...await describe(files.updaterSignature), signingKeyId: 'updater-1' },
    sbom: await describe(files.sbom),
    sigstore: { issuer: SIGSTORE_ISSUER, certificateIdentity: releaseIdentity(RELEASE_REPOSITORY, RELEASE_WORKFLOW, ref), transparencyLogRequired: true },
    windowsTrust: { authenticodeVerified: false, smartScreenReputationPromised: false, label: 'Unsigned Windows early-access build' },
    supportedWindows: 'Windows 10,Windows 11', releaseNotesUrl: 'https://usesesame.app/releases/1.2.3',
  }
  await writeFile(path.join(root, files.manifest), `${JSON.stringify(manifest, null, 2)}\n`)
  await writeFile(path.join(root, `${files.artifact}.sigstore.json`), '{"fictional":"artifact bundle"}\n')
  await writeFile(path.join(root, `${files.manifest}.sigstore.json`), '{"fictional":"manifest bundle"}\n')
  const evidence = {
    schemaVersion: 1, verified: true, transparencyLogVerified: true, issuer: manifest.sigstore.issuer, certificateIdentity: manifest.sigstore.certificateIdentity,
    repository: manifest.source.repository, workflow: manifest.source.workflow, ref: manifest.source.ref, sourceCommit: manifest.source.commit,
    artifactSha256: manifest.artifact.sha256, manifestSha256: await fileSha256(path.join(root, files.manifest)),
    artifactBundleSha256: await fileSha256(path.join(root, `${files.artifact}.sigstore.json`)), manifestBundleSha256: await fileSha256(path.join(root, `${files.manifest}.sigstore.json`)), verifiedAt: '2026-08-13T00:00:00.000Z',
  }
  await writeFile(path.join(root, 'sigstore-evidence.json'), `${JSON.stringify(evidence, null, 2)}\n`)
  await writeFile(path.join(root, 'SHA256SUMS'), `${manifest.artifact.sha256}  ${files.artifact}\n`)
  await writeFile(path.join(root, 'verify-sesame-release.ps1'), 'param([string]$Installer)\n')
  return { files, manifest, root }
}

test('release evidence binds the protected tag, exact workflow identity, and every published digest', async () => {
  const value = await fixture()
  try {
    const result = await validateEvidenceDirectory(value.root, value.files.manifest)
    assert.equal(result.manifest.artifact.sha256, value.manifest.artifact.sha256)
  } finally { await rm(value.root, { recursive: true, force: true }) }
})

test('release evidence rejects changed installer bytes and substituted Sigstore bundles', async () => {
  const changed = await fixture()
  try {
    await writeFile(path.join(changed.root, changed.files.artifact), 'changed installer bytes')
    await assert.rejects(validateEvidenceDirectory(changed.root, changed.files.manifest), /artifact does not match/)
  } finally { await rm(changed.root, { recursive: true, force: true }) }
  const bundle = await fixture()
  try {
    await writeFile(path.join(bundle.root, `${bundle.files.artifact}.sigstore.json`), '{"substituted":true}\n')
    await assert.rejects(validateEvidenceDirectory(bundle.root, bundle.files.manifest), /bundle was substituted/)
  } finally { await rm(bundle.root, { recursive: true, force: true }) }
})

test('release manifest rejects branch builds, forks, and a different workflow identity', async () => {
  const value = await fixture()
  try {
    const branch = structuredClone(value.manifest)
    branch.source.ref = 'refs/heads/main'
    assert.throws(() => validateReleaseManifest(branch), /protected Sesame tag/)
    const fork = structuredClone(value.manifest)
    fork.source.repository = 'attacker/Sesame'
    assert.throws(() => validateReleaseManifest(fork), /protected Sesame tag/)
    const workflow = structuredClone(value.manifest)
    workflow.sigstore.certificateIdentity = releaseIdentity(RELEASE_REPOSITORY, '.github/workflows/other.yml', workflow.source.ref)
    assert.throws(() => validateReleaseManifest(workflow), /Sigstore policy/)
  } finally { await rm(value.root, { recursive: true, force: true }) }
})

test('public evidence uses an explicit safe allowlist and rejects added secret material', async () => {
  const value = await fixture()
  const publicRoot = `${value.root}-public`
  try {
    await run(process.execPath, ['tools/prepare-public-release-evidence.mjs', value.root, publicRoot, value.files.manifest])
    await run(process.execPath, ['tools/audit-public-release-evidence.mjs', publicRoot])
    const names = (await readdir(publicRoot)).sort()
    assert.deepEqual(names, [
      'SHA256SUMS',
      `${value.files.artifact}.sigstore.json`,
      `${value.files.manifest}.sigstore.json`,
      'sesame-1.2.3.cdx.json',
      value.files.manifest,
      'sigstore-evidence.json',
      'verify-sesame-release.ps1',
    ].sort())
    assert.ok(!names.includes(value.files.artifact))
    assert.ok(!names.includes(value.files.updaterSignature))
    await writeFile(path.join(publicRoot, 'release-token.env'), 'SESAME_RELEASE_CANDIDATE_TOKEN=fictional\n')
    await assert.rejects(run(process.execPath, ['tools/audit-public-release-evidence.mjs', publicRoot]))
  } finally {
    await rm(value.root, { recursive: true, force: true })
    await rm(publicRoot, { recursive: true, force: true })
  }
})
