import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import test from 'node:test'

import { buildInventory, collectBundledLibraries, createDpkgResolver, defaultInventoryPath, readLibraryIdentity, readPackagingNote } from './create-appimage-sbom.mjs'

const root = path.resolve(import.meta.dirname, '..')
const align4 = (value) => Math.ceil(value / 4) * 4

function packagingNote(name, version) {
  const json = Buffer.from(JSON.stringify({ type: 'deb', os: 'Ubuntu', name, version, architecture: 'amd64' }), 'utf8')
  const header = Buffer.alloc(12)
  const payload = Buffer.alloc(align4(json.length))
  json.copy(payload)
  header.writeUInt32LE(4, 0)
  header.writeUInt32LE(payload.length, 4)
  header.writeUInt32LE(0xcafe1a7e, 8)
  return Buffer.concat([header, Buffer.from('FDO\0', 'utf8'), payload])
}

function elfHeader() {
  const header = Buffer.alloc(64)
  header.write('\x7fELF', 0, 'latin1')
  header[4] = 2
  header[5] = 1
  header[6] = 1
  header.writeUInt16LE(3, 16)
  header.writeUInt16LE(0x3e, 18)
  header.writeUInt32LE(1, 20)
  header.writeUInt16LE(64, 52)
  return header
}

function elfWithNote(name, version) {
  const header = elfHeader()
  header.writeUInt16LE(64, 58)
  header.writeUInt16LE(3, 60)
  header.writeUInt16LE(2, 62)
  header.writeBigUInt64LE(64n, 40)
  const sectionTable = Buffer.alloc(3 * 64)
  const note = packagingNote(name, version)
  const noteOffset = 64 + sectionTable.length
  const shstrtab = Buffer.from('\0.note.package\0.shstrtab\0', 'utf8')
  const shstrtabOffset = noteOffset + note.length
  sectionTable.writeUInt32LE(1, 64)
  sectionTable.writeUInt32LE(7, 64 + 4)
  sectionTable.writeBigUInt64LE(BigInt(noteOffset), 64 + 24)
  sectionTable.writeBigUInt64LE(BigInt(note.length), 64 + 32)
  sectionTable.writeBigUInt64LE(4n, 64 + 48)
  sectionTable.writeUInt32LE(15, 128)
  sectionTable.writeUInt32LE(3, 128 + 4)
  sectionTable.writeBigUInt64LE(BigInt(shstrtabOffset), 128 + 24)
  sectionTable.writeBigUInt64LE(BigInt(shstrtab.length), 128 + 32)
  sectionTable.writeBigUInt64LE(1n, 128 + 48)
  return Buffer.concat([header, sectionTable, note, shstrtab])
}

function elfWithText(text) {
  return Buffer.concat([elfHeader(), Buffer.from(text, 'utf8')])
}

function fixtureTree() {
  const tree = mkdtempSync(path.join(tmpdir(), 'sesame-appimage-fixture-'))
  mkdirSync(path.join(tree, 'usr', 'lib', 'gtk-3.0', '3.0.0', 'immodules'), { recursive: true })
  writeFileSync(path.join(tree, 'usr', 'lib', 'libfictional.so.1'), elfWithNote('fictional-source', '1.2.3-4ubuntu5'))
  symlinkSync('libfictional.so.1', path.join(tree, 'usr', 'lib', 'libfictional.so'))
  writeFileSync(
    path.join(tree, 'usr', 'lib', 'gtk-3.0', '3.0.0', 'immodules', 'im-fictional.so'),
    elfWithText('im-fictional immodule 2.0.0'),
  )
  writeFileSync(path.join(tree, 'usr', 'lib', 'notes.txt'), 'fictional notes')
  return tree
}

test('a packaging note supplies the exact Ubuntu source identity', () => {
  assert.deepEqual(readPackagingNote(elfWithNote('fictional-source', '1.2.3-4ubuntu5')), {
    name: 'fictional-source',
    version: '1.2.3-4ubuntu5',
  })
  assert.equal(readPackagingNote(elfWithText('no packaging note here')), null)
})

test('a version string beside the library name is read as a fallback identity', () => {
  assert.deepEqual(readLibraryIdentity(elfWithText('fictional library version 9.8.7 ready'), 'libfictional.so.1'), {
    name: 'fictional',
    version: '9.8.7',
  })
  assert.equal(readLibraryIdentity(elfWithText('nothing to see here'), 'libfictional.so.1'), null)
})

test('the inventory collects ELF shared objects recursively and deduplicates symlinks', async () => {
  const tree = fixtureTree()
  try {
    const libraries = await collectBundledLibraries(tree)
    assert.deepEqual(libraries.map((library) => library.library), ['im-fictional.so', 'libfictional.so'])
    assert.deepEqual(libraries.find((library) => library.library === 'libfictional.so').names, [
      'libfictional.so',
      'libfictional.so.1',
    ])
  } finally {
    rmSync(tree, { recursive: true, force: true })
  }
})

test('resolved libraries become pkg:deb/ubuntu components and deduplicate by package', async () => {
  const tree = fixtureTree()
  try {
    const inventory = await buildInventory(tree, {
      resolvePackage: async () => ({ name: 'fictional-source', version: '1.2.3-4ubuntu5' }),
    })
    assert.equal(inventory.libraries, 2)
    assert.equal(inventory.components.length, 1)
    const [component] = inventory.components
    assert.equal(component.purl, 'pkg:deb/ubuntu/fictional-source@1.2.3-4ubuntu5')
    assert.equal(component.properties.filter((property) => property.name === 'sesame:bundled-library').length, 2)
    assert.equal(inventory.byIdentity.note, 1)
    assert.equal(inventory.byIdentity.dpkg, 1)
  } finally {
    rmSync(tree, { recursive: true, force: true })
  }
})

test('a library with no readable version is reported instead of silently passing', () => {
  const tree = mkdtempSync(path.join(tmpdir(), 'sesame-appimage-unresolved-'))
  try {
    mkdirSync(path.join(tree, 'usr', 'lib'), { recursive: true })
    writeFileSync(path.join(tree, 'usr', 'lib', 'libmystery.so.1'), elfWithText('mystery without a version'))
    const out = path.join(tree, 'inventory.cdx.json')
    const result = spawnSync(process.execPath, ['tools/create-appimage-sbom.mjs', '--tree', tree, '--out', out], {
      cwd: root,
      encoding: 'utf8',
    })
    assert.equal(result.status, 1)
    assert.match(result.stderr, /libmystery\.so\.1/)
  } finally {
    rmSync(tree, { recursive: true, force: true })
  }
})

test('the inventory command writes CycloneDX with Ubuntu purls for resolvable libraries', () => {
  const tree = fixtureTree()
  try {
    const out = path.join(tree, 'sesame-appimage.cdx.json')
    const result = spawnSync(process.execPath, ['tools/create-appimage-sbom.mjs', '--tree', tree, '--out', out], {
      cwd: root,
      encoding: 'utf8',
    })
    assert.equal(result.status, 0, result.stderr)
    const bom = JSON.parse(readFileSync(out, 'utf8'))
    assert.equal(bom.bomFormat, 'CycloneDX')
    assert.equal(bom.components.length, 2)
    for (const component of bom.components) {
      assert.match(component.purl, /^pkg:deb\/ubuntu\/[^@]+@[^@]+$/)
    }
  } finally {
    rmSync(tree, { recursive: true, force: true })
  }
})

test('dpkg source metadata is parsed into a source package identity', async () => {
  const calls = []
  const query = async (args) => {
    calls.push(args)
    if (args[0] === '-S') return 'fictional-binary:amd64: /usr/lib/x86_64-linux-gnu/libfictional.so.1\n'
    return 'fictional-source\t1.2.3-4ubuntu5\n'
  }
  const resolver = createDpkgResolver({ query })
  assert.deepEqual(await resolver(['libfictional.so.1']), { name: 'fictional-source', version: '1.2.3-4ubuntu5' })
  assert.deepEqual(calls[0], ['-S', '*/libfictional.so.1'])
  assert.deepEqual(calls[1], ['-W', '-f=${source:Package}\t${source:Version}\n', 'fictional-binary:amd64'])
})

test('an ambiguous file owner falls through and a later library name can resolve', async () => {
  const query = async (args) => {
    if (args[0] === '-S' && args[1].includes('libambiguous')) {
      return 'fictional-one:amd64: /usr/lib/x86_64-linux-gnu/libambiguous.so.1\nfictional-two:amd64: /usr/lib/x86_64-linux-gnu/libambiguous.so.1\n'
    }
    if (args[0] === '-S' && args[1].includes('libthree')) {
      return 'fictional-three:amd64: /usr/lib/x86_64-linux-gnu/libthree.so.1\n'
    }
    if (args[0] === '-S') return ''
    if (args[2]?.includes('fictional-one')) return 'fictional-source-one\t1.0.0\n'
    if (args[2]?.includes('fictional-two')) return 'fictional-source-two\t2.0.0\n'
    if (args[2]?.includes('fictional-three')) return 'fictional-source-three\t3.0.0\n'
    return ''
  }
  const resolver = createDpkgResolver({ query })
  assert.equal(await resolver(['libambiguous.so.1']), null)
  assert.deepEqual(await resolver(['libmissing.so.1', 'libthree.so.1']), {
    name: 'fictional-source-three',
    version: '3.0.0',
  })
})

test('the default inventory path matches the AppImage suffix', () => {
  const previous = process.env.SESAME_SBOM_OUTPUT_DIR
  delete process.env.SESAME_SBOM_OUTPUT_DIR
  try {
    const version = JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8')).version
    assert.equal(defaultInventoryPath(root), path.join(root, 'release-evidence', `sesame-${version}-appimage.cdx.json`))
  } finally {
    if (previous !== undefined) process.env.SESAME_SBOM_OUTPUT_DIR = previous
  }
})
