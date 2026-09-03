import assert from 'node:assert/strict'
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import test from 'node:test'

import { discoverLinuxPackages } from './release-platforms/linux.mjs'
import { discoverWindowsPackages } from './release-platforms/windows.mjs'
import { RELEASE_REPOSITORY, RELEASE_WORKFLOW, SIGSTORE_ISSUER, releaseIdentity } from './release-evidence-lib.mjs'
import { prepareReleaseSet, reconcileReleaseSet, verifyReleaseSet } from './release-set.mjs'

const version = '1.2.3'
const architecture = 'x86_64'
const ref = `refs/tags/v${version}`
const identity = releaseIdentity(RELEASE_REPOSITORY, RELEASE_WORKFLOW, ref)

function artifact(format, character = format[0]) {
  const sha256 = character.repeat(64)
  const updaterCapable = format === 'nsis'
  return {
    format,
    architecture,
    url: `https://downloads.example.invalid/${format}/Sesame.${format}`,
    objectKey: `windows/${version}/Sesame.${format}`,
    sha256,
    bytes: 42,
    updaterCapable,
    updaterSignature: updaterCapable ? 's'.repeat(64) : '',
    updaterSigningKeyId: updaterCapable ? 'fictional-updater-key' : '',
    distributionClass: 'early_access',
    sigstoreEvidence: {
      schemaVersion: 1,
      verified: true,
      transparencyLogVerified: true,
      issuer: SIGSTORE_ISSUER,
      certificateIdentity: identity,
      repository: RELEASE_REPOSITORY,
      workflow: RELEASE_WORKFLOW,
      ref,
      artifactSha256: sha256,
      artifactBundleSha256: 'b'.repeat(64),
    },
    sigstoreVerified: true,
    sigstoreIssuer: SIGSTORE_ISSUER,
    sigstoreIdentity: identity,
    sigstoreBundleSha256: 'b'.repeat(64),
    authenticodeVerified: false,
  }
}

function windowsSet() {
  return prepareReleaseSet({
    version,
    channel: 'beta',
    platform: 'windows',
    architecture,
    supportedWindows: 'Windows 10,Windows 11',
    releaseNotesUrl: `https://example.invalid/releases/${version}`,
    artifacts: [artifact('nsis', 'a')],
  })
}

test('prepare and verify bind every immutable package field into one set digest', () => {
  const releaseSet = windowsSet()
  assert.equal(verifyReleaseSet(releaseSet), releaseSet)
  const changed = structuredClone(releaseSet)
  changed.artifacts[0].bytes++
  assert.throws(() => verifyReleaseSet(changed), /digest does not match/)
})

test('release URLs reject unsigned query parameters', () => {
  const notesQuery = structuredClone(windowsSet())
  notesQuery.releaseNotesUrl += '?channel=other'
  assert.throws(() => verifyReleaseSet(notesQuery), /credential-free HTTPS URL/)
  const artifactQuery = structuredClone(windowsSet())
  artifactQuery.artifacts[0].url += '?download=other'
  assert.throws(() => verifyReleaseSet(artifactQuery), /credential-free HTTPS URL/)
})

test('release set digest matches the server candidate contract', () => {
  const nsis = artifact('nsis', 'a')
  nsis.url = 'https://downloads.example.invalid/Sesame.exe'
  nsis.objectKey = 'releases/0.2.3/Sesame.exe'
  nsis.bytes = 1
  nsis.updaterSignature = 's'.repeat(64)
  nsis.updaterSigningKeyId = 'test-updater-key'
  nsis.sigstoreIdentity = releaseIdentity(RELEASE_REPOSITORY, RELEASE_WORKFLOW, 'refs/tags/v0.2.3')
  nsis.sigstoreEvidence.certificateIdentity = nsis.sigstoreIdentity
  nsis.sigstoreEvidence.ref = 'refs/tags/v0.2.3'
  const releaseSet = prepareReleaseSet({
    version: '0.2.3',
    channel: 'beta',
    platform: 'windows',
    architecture,
    supportedWindows: 'Windows 10',
    releaseNotesUrl: 'https://example.invalid/releases/0.2.3',
    artifacts: [nsis],
  })
  assert.equal(releaseSet.setDigest, 'ace8b84e98af42c87ceab7694ac1a3b4e77679995809cd299e5110a93f3dd154')
})

test('verification rejects missing, duplicate, and inapplicable package records', () => {
  const linux = {
    version,
    channel: 'beta',
    platform: 'linux',
    architecture,
    supportedWindows: '',
    releaseNotesUrl: `https://example.invalid/releases/${version}`,
    artifacts: [artifact('appimage', 'a'), artifact('deb', 'd')],
  }
  assert.throws(() => prepareReleaseSet(linux), /missing required formats: rpm/)
  const duplicate = structuredClone(windowsSet())
  duplicate.artifacts.push(duplicate.artifacts[0])
  assert.throws(() => verifyReleaseSet(duplicate), /duplicate nsis:x86_64/)
})

test('reconciliation reports missing and conflicting immutable records', () => {
  const expected = windowsSet()
  const missing = structuredClone(expected)
  missing.artifacts = []
  assert.deepEqual(reconcileReleaseSet(expected, missing).missing, ['nsis:x86_64'])
  const conflicting = structuredClone(expected)
  conflicting.artifacts[0].sha256 = 'c'.repeat(64)
  assert.deepEqual(reconcileReleaseSet(expected, conflicting).conflicts, ['nsis:x86_64'])
  assert.deepEqual(reconcileReleaseSet(expected, null), {
    complete: false,
    missing: ['nsis:x86_64'],
    conflicts: ['release-set'],
  })
})

test('platform adapters own exact Windows and Linux package discovery', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'sesame-release-set-'))
  try {
    for (const directory of ['nsis', 'appimage', 'deb', 'rpm']) await mkdir(path.join(root, directory))
    await writeFile(path.join(root, 'nsis', 'Sesame-setup.exe'), 'fictional NSIS package')
    await writeFile(path.join(root, 'nsis', 'Sesame-setup.exe.sig'), 's'.repeat(64))
    await writeFile(path.join(root, 'appimage', 'Sesame.AppImage'), 'fictional AppImage package')
    await writeFile(path.join(root, 'deb', 'Sesame.deb'), 'fictional DEB package')
    await writeFile(path.join(root, 'rpm', 'Sesame.rpm'), 'fictional RPM package')
    assert.deepEqual((await discoverWindowsPackages(root, architecture)).map(({ format, updaterCapable }) => ({ format, updaterCapable })), [{ format: 'nsis', updaterCapable: true }])
    assert.deepEqual((await discoverLinuxPackages(root, architecture)).map(({ format, updaterCapable }) => ({ format, updaterCapable })), [
      { format: 'appimage', updaterCapable: false },
      { format: 'deb', updaterCapable: false },
      { format: 'rpm', updaterCapable: false },
    ])
    await rm(path.join(root, 'nsis', 'Sesame-setup.exe.sig'))
    await assert.rejects(discoverWindowsPackages(root, architecture), /did not find a regular NSIS updater signature file/)
    await mkdir(path.join(root, 'nsis', 'Sesame-setup.exe.sig'))
    await assert.rejects(discoverWindowsPackages(root, architecture), /did not find a regular NSIS updater signature file/)
    await writeFile(path.join(root, 'rpm', 'Sesame-copy.rpm'), 'conflicting fictional RPM package')
    await assert.rejects(discoverLinuxPackages(root, architecture), /found 2 rpm packages/)
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})
