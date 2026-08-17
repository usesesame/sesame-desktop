import assert from 'node:assert/strict'
import { readdirSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

const projectRoot = dirname(dirname(fileURLToPath(import.meta.url)))
const uiRoot = join(projectRoot, 'src', 'lib', 'ui')
const componentPaths = readdirSync(uiRoot)
  .filter((name) => name.endsWith('.svelte'))
  .map((name) => join(uiRoot, name))

const read = (path) => readFileSync(path, 'utf8')
const component = (name) => read(join(uiRoot, name))
const occurrences = (source, value) => source.split(value).length - 1

test('ModalShell owns labelled dialog, focus trap, Escape, and focus restoration', () => {
  const source = component('ModalShell.svelte')
  assert.match(source, /role="dialog"/)
  assert.match(source, /aria-modal="true"/)
  assert.match(source, /aria-labelledby=\{labelledby\}/)
  assert.match(source, /event\.key === 'Escape'/)
  assert.match(source, /event\.key !== 'Tab'/)
  assert.match(source, /isTopmostModal\(\)/)
  assert.match(source, /onDestroy\(restoreFocus\)/)
  assert.match(source, /target\.focus\(\{ preventScroll: true \}\)/)
})

test('every modal delegates semantics to ModalShell and names its dialog', () => {
  for (const path of componentPaths) {
    const source = read(path)
    if (!source.includes('<ModalShell')) continue

    assert.equal(
      occurrences(source, '<ModalShell'),
      [...source.matchAll(/\slabelledby=/g)].length,
      `${path} must label every ModalShell`,
    )

    for (const [, labelId] of source.matchAll(/\slabelledby="([^"]+)"/g)) {
      assert.ok(source.includes(`id="${labelId}"`), `${path} is missing the labelledby target #${labelId}`)
    }
    for (const [, descriptionId] of source.matchAll(/\sdescribedby="([^"]+)"/g)) {
      assert.ok(source.includes(`id="${descriptionId}"`), `${path} is missing the describedby target #${descriptionId}`)
    }
  }

  const handRolledDialogs = componentPaths
    .filter((path) => !path.endsWith('ModalShell.svelte'))
    .filter((path) => /<(?:div|section|main|aside)\b[^>]*\srole="dialog"/.test(read(path)))
  assert.deepEqual(handRolledDialogs, [], 'dialogs must use ModalShell rather than duplicating focus behavior')
})

test('settings tabs implement the ARIA tabs keyboard pattern', () => {
  const source = component('SettingsView.svelte')
  for (const contract of [
    'role="tablist"',
    'role="tab"',
    'aria-controls=',
    'aria-selected=',
    'tabindex={tab === item.id ? 0 : -1}',
    'role="tabpanel"',
    'aria-labelledby=',
    "event.key === 'ArrowRight'",
    "event.key === 'ArrowLeft'",
    "event.key === 'Home'",
    "event.key === 'End'",
  ]) assert.ok(source.includes(contract), `SettingsView is missing ${contract}`)
})

test('tools tabs implement the same ARIA tabs keyboard pattern as settings', () => {
  const source = component('ToolsView.svelte')
  for (const contract of [
    'role="tablist"',
    'role="tab"',
    'aria-controls=',
    'aria-selected=',
    'tabindex={tab === item.id ? 0 : -1}',
    'role="tabpanel"',
    'aria-labelledby=',
    "event.key === 'ArrowRight'",
    "event.key === 'ArrowLeft'",
    "event.key === 'Home'",
    "event.key === 'End'",
  ]) assert.ok(source.includes(contract), `ToolsView is missing ${contract}`)
})

test('import format picker implements listbox navigation and dismissal', () => {
  const source = component('ImportModal.svelte')
  for (const contract of [
    'aria-haspopup="listbox"',
    'role="listbox"',
    'role="option"',
    'aria-selected=',
    'tabindex="-1"',
    'handleOptionKeydown',
    "event.key === 'ArrowDown'",
    "event.key === 'ArrowUp'",
    "event.key === 'Home'",
    "event.key === 'End'",
    "event.key === 'Escape'",
    'event.stopPropagation()',
  ]) assert.ok(source.includes(contract), `ImportModal is missing ${contract}`)
})

test('entry context menu supports scoped menu and submenu navigation', () => {
  const source = component('EntryContextMenu.svelte')
  for (const contract of [
    'role="menu"',
    'role="menuitem"',
    'role="menuitemradio"',
    'aria-checked=',
    'aria-haspopup="menu"',
    'aria-controls="entry-folder-submenu"',
    "event.key === 'ArrowRight'",
    "event.key === 'ArrowLeft'",
    "event.key === 'ArrowDown'",
    "event.key === 'ArrowUp'",
    "event.key === 'Home'",
    "event.key === 'End'",
    "event.key === 'Escape'",
  ]) assert.ok(source.includes(contract), `EntryContextMenu is missing ${contract}`)
})

test('unlock and recovery screen changes place focus deliberately', () => {
  const unlock = component('UnlockScreen.svelte')
  assert.match(unlock, /bind:this=\{masterPasswordInput\}/)
  assert.match(unlock, /await tick\(\)/)
  assert.match(unlock, /masterPasswordInput\?\.focus\(\)/)
  assert.match(unlock, /aria-invalid=/)
  assert.match(unlock, /role="alert"/)

  const recovery = component('RecoveryKitScreen.svelte')
  assert.match(recovery, /tabindex="-1"/)
  assert.match(recovery, /heading\?\.focus\(\{ preventScroll: true \}\)/)
  assert.match(recovery, /aria-labelledby="recovery-kit-heading"/)
})

test('workspace changes and notifications are announced without moving focus', () => {
  const workspace = component('WorkspaceShell.svelte')
  assert.match(workspace, /aria-labelledby="workspace-heading"/)
  assert.match(workspace, /role="status"/)
  assert.match(workspace, /aria-live="polite"/)

  const toast = component('Toast.svelte')
  assert.match(toast, /role="status" aria-live="polite" aria-atomic="true"/)
  assert.match(toast, /role="alert" aria-atomic="true"/)
})

test('interactive Svelte components do not introduce positive tabindex values', () => {
  for (const path of componentPaths) {
    assert.doesNotMatch(read(path), /tabindex\s*=\s*["'][1-9]\d*["']/, `${path} contains a positive tabindex`)
  }
})

test('custom window controls expose names and native button behavior', () => {
  const source = component('AppChrome.svelte')
  const group = source.match(/<div class="window-controls"[\s\S]*?<\/div>/)
  assert.ok(group, 'AppChrome no longer has a window-controls group this test can read')
  const controls = [...group[0].matchAll(/<button\b[\s\S]*?<\/button>/g)].map((match) => match[0])
  assert.equal(controls.length, 3)
  for (const control of controls) {
    assert.match(control, /type="button"/)
    assert.match(control, /aria-label=/)
  }
})

const appSource = read(join(projectRoot, 'src', 'App.svelte'))
const modalHostPattern = /<ModalHost\b[\s\S]*?<\/ModalHost>/
const modalHostMatch = appSource.match(modalHostPattern)

const ordinaryModals = [
  'PinSetupModal',
  'ChangeMasterPasswordModal',
  'DataControlsModal',
  'DeleteVaultModal',
  'ConfirmDeleteModal',
  'ConfirmMergeModal',
  'RestoreModal',
  'BackupDrillModal',
  'LoginEditor',
  'IdentityEditor',
  'ConfirmDeleteIdentityModal',
  'ImportModal',
  'FolderManagerModal',
  'FolderNameModal',
]

const nonHostedModals = ['BrowserFillApprovalModal', 'BrowserIdentityFillApprovalModal', 'BetaOnboarding']

test('all ordinary modals render through a single ModalHost in App.svelte', () => {
  assert.ok(modalHostMatch, 'App.svelte must have one ModalHost')
  const modalHostSource = modalHostMatch[0]
  for (const modal of ordinaryModals) {
    assert.ok(modalHostSource.includes(`<${modal}`), `${modal} must be rendered inside ModalHost`)
  }
  for (const modal of nonHostedModals) {
    assert.ok(appSource.includes(`<${modal}`), `${modal} must still be rendered in App.svelte`)
    assert.ok(!modalHostSource.includes(`<${modal}`), `${modal} must not be rendered inside ModalHost`)
  }
})

test('no migrated modal is mounted with a direct store conditional outside ModalHost', () => {
  assert.ok(modalHostMatch, 'App.svelte must have one ModalHost')
  const outsideModalHost = appSource.replace(modalHostPattern, '')
  const directMigratedConditionals = [
    /\{#if\s+\$cleanupState\.dataControlsOpen/,
    /\{#if\s+\$cleanupState\.deleteVaultOpen/,
    /\{#if\s+\$cleanupState\.deleteCandidate/,
    /\{#if\s+\$cleanupState\.mergeCandidate/,
    /\{#if\s+\$backupState\.restoreSelection/,
    /\{#if\s+\$backupState\.drillOpen/,
    /\{#if\s+\$loginState\.editorOpen/,
    /\{#if\s+\$loginState\.folderManagerOpen/,
    /\{#if\s+\$loginState\.folderAction/,
    /\{#if\s+\$imports\.open/,
  ]
  for (const pattern of directMigratedConditionals) {
    assert.doesNotMatch(outsideModalHost, pattern, 'migrated modals must not use direct store conditionals outside ModalHost')
  }
})

test('ModalHost leaves guarded Escape handling to each ModalShell', () => {
  const source = read(join(projectRoot, 'src', 'lib', 'ui', 'ModalHost.svelte'))
  assert.doesNotMatch(source, /<svelte:window/)
  assert.doesNotMatch(source, /stopImmediatePropagation/)
})

const modalControllerSource = read(join(projectRoot, 'src', 'lib', 'controllers', 'modal-controller.ts'))

test('ModalController keeps conflicting dialogs mutually exclusive', () => {
  assert.match(modalControllerSource, /function modalKindsConflict/)
  assert.match(modalControllerSource, /a === 'restore' \|\| b === 'restore'/)
  assert.match(modalControllerSource, /return true/)
})

test('ModalController lockCleared closes every modal', () => {
  assert.match(modalControllerSource, /function lockCleared\(\)/)
  assert.match(modalControllerSource, /closeAll\(\)/)
})

const recoveryScreenSource = read(join(projectRoot, 'src', 'lib', 'ui', 'RecoveryKitScreen.svelte'))
const unlockControllerSource = read(join(projectRoot, 'src', 'lib', 'controllers', 'unlock-controller.ts'))
const onboardingControllerSource = read(join(projectRoot, 'src', 'lib', 'controllers', 'onboarding-controller.ts'))

test('recovery display and verification use separate guarded transitions', () => {
  assert.match(appSource, /\{#key \$onboardingState\.step\}/)
  assert.match(appSource, /recovery-verify' \? unlockController\.finishRecoveryKit : unlockController\.continueRecoveryKitSetup/)
  assert.match(recoveryScreenSource, /verifyGroups\.length === 2/)
  assert.match(recoveryScreenSource, /\$: readyToSubmit/)
  const displayTransition = unlockControllerSource.match(/continueRecoveryKitSetup\(\)[\s\S]*?\},/)?.[0] ?? ''
  assert.doesNotMatch(displayTransition, /recoveryKit:\s*''/)
  assert.match(displayTransition, /onboarding\.advance\(\)/)
  const verifiedTransition = unlockControllerSource.match(/async finishRecoveryKit\(\)[\s\S]*?\},/)?.[0] ?? ''
  assert.match(verifiedTransition, /recoveryKit:\s*''/)
})

test('PIN completion advances onboarding and the flow has no unrendered backup step', () => {
  const settingsSource = read(join(projectRoot, 'src', 'lib', 'controllers', 'settings-controller.ts'))
  assert.match(settingsSource, /closePinSetup\(\)[\s\S]*?onPinSetupFinished\(\)/)
  assert.match(settingsSource, /async savePin\(\)[\s\S]*?onPinSetupFinished\(\)/)
  assert.doesNotMatch(onboardingControllerSource, /backup-prompt/)
})

test('browser fill and ordinary modals refuse overlapping blocking surfaces', () => {
  const browserFillSource = read(join(projectRoot, 'src', 'lib', 'controllers', 'browser-fill-controller.ts'))
  assert.match(modalControllerSource, /stores\.browserFill\.value\(\)\.request/)
  assert.match(browserFillSource, /blockingOverlayActive\(\)/)
})

test('identity fill shares the same overlapping-surface guard as browser fill', () => {
  const identityFillSource = read(join(projectRoot, 'src', 'lib', 'controllers', 'identity-fill-controller.ts'))
  assert.match(modalControllerSource, /stores\.browserIdentityFill\.value\(\)\.request/)
  assert.match(identityFillSource, /blockingOverlayActive\(\)/)
})

const controllersDir = join(projectRoot, 'src', 'lib', 'controllers')
const controllerNames = ['cleanup-controller.ts', 'import-controller.ts', 'backup-controller.ts', 'login-controller.ts']

test('controllers clear their modal and secrets on clearSecrets', () => {
  for (const name of controllerNames) {
    const source = read(join(controllersDir, name))
    const hasClearSecrets = /clearSecrets\(\)/.test(source)
    assert.ok(hasClearSecrets, `${name} must define clearSecrets`)
    const closesModal = /modal\.closeAll\(\)/.test(source) || /modal\.close\(/.test(source)
    assert.ok(closesModal, `${name} clearSecrets must close its modal`)
  }
})

test('healthy desktop browser plumbing is not shown as extension installation', () => {
  const source = component('BrowserIntegrationSetting.svelte')
  assert.match(source, /does not confirm that the browser extension is installed/)
  assert.match(source, />Browser autofill setup</)
  assert.match(source, /Recheck desktop setup/)
  assert.doesNotMatch(source, /\? 'Installed'/)
  const settings = component('SettingsView.svelte')
  assert.match(settings, /{#if !browserIntegration\?\.ready\}[\s\S]*?<BrowserIntegrationSetting/)
})

test('PanelResizer is an operable window splitter, not a decorative bar', () => {
  const source = component('PanelResizer.svelte')
  assert.match(source, /role="separator"/)
  assert.match(source, /aria-orientation="vertical"/)
  assert.match(source, /aria-valuenow=\{value\}/)
  assert.match(source, /aria-valuemin=\{min\}/)
  assert.match(source, /aria-valuemax=\{max\}/)
  assert.match(source, /tabindex="0"/)
  assert.match(source, /aria-label=\{label\}/)

  assert.match(source, /event\.key === 'ArrowLeft'/)
  assert.match(source, /event\.key === 'ArrowRight'/)
  assert.match(source, /event\.key === 'Home'/)
  assert.match(source, /event\.key === 'End'/)

  assert.match(source, /setPointerCapture/)
  assert.match(source, /releasePointerCapture/)
})

test('locking the vault clears the recently viewed trail', () => {
  const controller = read(join(projectRoot, 'src', 'lib', 'controllers', 'login-controller.ts'))
  const clearSecrets = controller.slice(controller.indexOf('clearSecrets()'))
  const body = clearSecrets.slice(0, clearSecrets.indexOf('\n    },'))
  assert.match(
    body,
    /recentEntryIds: \[\]/,
    'clearSecrets must empty recentEntryIds so a lock leaves no trail of what was open',
  )
})

test('the recently viewed strip stores ids, never vault content', () => {
  const stores = read(join(projectRoot, 'src', 'lib', 'stores', 'app-stores.ts'))
  assert.match(stores, /recentEntryIds: string\[\]/, 'recentEntryIds must hold ids only')
})

test('the vault grid has a track for every child it renders', () => {
  const view = component('VaultView.svelte')
  const layoutStart = view.indexOf('<div class="vault-layout"')
  assert.ok(layoutStart >= 0, 'VaultView must render .vault-layout')

  const children = [...view.slice(layoutStart).matchAll(/^ {4}<(section|aside|PanelResizer)\b/gm)].length
  const css = read(join(projectRoot, 'src', 'app.css'))
  const tracks = css
    .slice(css.indexOf('.vault-layout {'))
    .match(/grid-template-columns:([^;]+);/)[1]
    .trim()
    .split(/\s+(?![^(]*\))/)
    .filter(Boolean).length

  assert.equal(
    children,
    tracks,
    `.vault-layout renders ${children} children but declares ${tracks} columns. Grid overflows into new rows silently.`,
  )
})

test('the panel resizer is styled globally, not scoped to its component', () => {
  const resizer = component('PanelResizer.svelte')
  assert.ok(!resizer.includes('<style>'), 'PanelResizer must not carry scoped styles')

  const css = read(join(projectRoot, 'src', 'app.css'))
  assert.match(css, /^\.panel-resizer \{/m, 'app.css must own the .panel-resizer rule')
  assert.match(
    css,
    /@media \(max-width: 1280px\)[\s\S]{0,400}?\.panel-resizer \{ display: none; \}/,
    'the handles must hide at the breakpoint where the rail is hidden',
  )
})

test('every listed shortcut is bound, and every bound shortcut is listed', () => {
  const shortcuts = read(join(projectRoot, 'src', 'lib', 'shortcuts.ts'))
  const shell = component('WorkspaceShell.svelte')
  const settings = component('SettingsView.svelte')

  const listed = [...shortcuts.matchAll(/keys: '([^']+)'/g)].map((match) => match[1])
  assert.ok(listed.length > 0, 'src/lib/shortcuts.ts declares no shortcuts')

  assert.match(settings, /import \{ SHORTCUTS \} from '\.\.\/shortcuts'/)
  assert.match(settings, /#each SHORTCUTS as shortcut/)

  for (const keys of listed) {
    const letter = keys.split(' ').at(-1).toLowerCase()
    assert.match(
      shell,
      new RegExp(`key === '${letter}'`),
      `${keys} is listed in Settings but WorkspaceShell binds no '${letter}' key`,
    )
  }

  for (const [, letter] of shell.matchAll(/key === '([a-z])'/g)) {
    assert.ok(
      listed.some((keys) => keys.split(' ').at(-1).toLowerCase() === letter),
      `WorkspaceShell binds '${letter}' but it is not in src/lib/shortcuts.ts, so nobody can discover it`,
    )
  }

  const guard = shell.match(/if \(typing\) return/)
  assert.ok(guard, 'WorkspaceShell no longer skips shortcuts while a field has focus')
  assert.ok(
    shell.indexOf("key === 'l'") < shell.indexOf('if (typing) return'),
    'the lock shortcut moved below the typing guard, so it no longer works from inside a field',
  )
  assert.match(shell, /!\$vault\.status\.unlocked\) return/, 'shortcuts no longer require an unlocked vault')
})
