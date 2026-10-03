<script lang="ts">
  import Icon from '../Icon.svelte'
  import DuplicateReview from './DuplicateReview.svelte'
  import ViewHeader from './ViewHeader.svelte'
  import WebsiteIcon from './WebsiteIcon.svelte'
  import { issueKindLabels } from '../issue-kinds'
  import type { BreachScanReport, CleanupEntry, DuplicateGroup, IssueKind, TwoFactorSiteLogin, VaultSnapshot } from '../types'

  export let duplicateReviewOpen = false
  export let duplicateReviewLoading = false
  export let duplicateGroups: DuplicateGroup[] = []
  export let duplicateGroupId: string | undefined = undefined
  export let duplicateSelectedIds: string[] = []
  export let snapshot: VaultSnapshot | null = null
  export let onSelectGroup: (groupId: string) => void
  export let onSelectEntry: (entryId: string, selected: boolean) => void
  export let onEdit: (entry: CleanupEntry) => void
  export let onMerge: (group: DuplicateGroup, entries: CleanupEntry[]) => void
  export let onDelete: (entry: CleanupEntry) => void
  export let onOpenDuplicateReview: () => void
  export let onShowSecurityFilter: (filter: Exclude<IssueKind, 'duplicate'>) => void
  export let onShowCards: () => void
  export let breachScan: BreachScanReport | null = null
  export let breachScanError = ''
  export let onStartBreachScan: () => void
  export let onCancelBreachScan: () => void
  export let onOpenLogin: (id: string) => void
  export let siteIconsEnabled = false

  type Finding = {
    key: string
    title: string
    icon: string
    count: number
    activeText: string
    clearText: string
    weight: number
    danger?: boolean
    onClick?: () => void
    logins?: TwoFactorSiteLogin[]
  }

  const DISPLAY_LIMIT = 5

  $: goodCount = snapshot?.security.good ?? 0
  $: loginCount = snapshot?.entries.length ?? 0
  $: security = snapshot?.security

  function loginFinding(kind: Exclude<IssueKind, 'duplicate'>, icon: string, count: number, activeText: string, clearText: string, weight: number): Finding {
    return { key: kind, title: issueKindLabels[kind].title, icon, count, activeText, clearText, weight, onClick: () => onShowSecurityFilter(kind) }
  }

  $: findings = ([
    { key: 'expired-cards', title: 'Expired cards', icon: 'card', count: security?.expiredCards ?? 0, activeText: 'Replace these cards before a payment fails', clearText: 'No expired cards on file', weight: 0, danger: true, onClick: onShowCards },
    loginFinding('reused-password', 'copy', security?.reusedPasswords ?? 0, 'One leaked account could expose another', 'No reused passwords found', 1),
    loginFinding('compromised-pattern', 'shield-alert', security?.compromisedPatterns ?? 0, 'Predictable sequences and breached-style patterns', 'No unsafe password patterns found', 2),
    loginFinding('weak-password', 'key', security?.weakPasswords ?? 0, 'Short or low-variety passwords to replace', 'No weak passwords found', 3),
    loginFinding('common-password', 'alert', security?.commonPasswords ?? 0, 'Passwords attackers are likely to try first', 'No common passwords found', 4),
    loginFinding('totp', 'shield-alert', security?.noTotp ?? 0, 'Accounts without a stored code', 'Every login has 2FA saved', 5),
    { key: 'expiring-cards', title: 'Cards expiring soon', icon: 'card', count: security?.expiringCards ?? 0, activeText: 'These cards stop working within 30 days', clearText: 'No cards expire in the next 30 days', weight: 6, onClick: onShowCards },
    loginFinding('recovery', 'file-key', security?.missingRecovery ?? 0, 'Logins with no saved recovery option', "Every login's recovery is reviewed", 7),
    loginFinding('old-password', 'refresh', security?.oldPasswords ?? 0, 'Not changed in over a year', 'Every password was changed in the last year', 8),
    { key: 'duplicate', title: issueKindLabels.duplicate.title, icon: 'copy', count: security?.duplicateCandidates ?? 0, activeText: 'Review and merge likely matches', clearText: 'Nothing to merge', weight: 9, onClick: onOpenDuplicateReview },
    loginFinding('url', 'globe', security?.missingUrls ?? 0, 'Add the sign-in site to these logins', 'Every login has a website', 10),
    { key: 'two-factor-sites', title: 'Sites that offer 2FA', icon: 'shield', count: security?.twoFactorSites ?? 0, activeText: 'These sites support 2FA or passkeys. Sesame does not know whether it is switched on.', clearText: 'No saved site is on the bundled 2FA list', weight: 11, logins: security?.twoFactorLogins ?? [] },
  ] as Finding[]).sort((a, b) => a.weight - b.weight)

  $: actionableFindings = findings.filter((finding) => finding.count > 0)
  $: clearFindings = findings.filter((finding) => finding.count === 0)

  $: breachedResults = breachScan?.phase === 'finished' ? breachScan.results.filter((result) => result.verdict === 'breached') : []
  $: unknownResults = breachScan?.phase === 'finished' ? breachScan.results.filter((result) => result.verdict === 'unknown') : []
  $: progressPercent = breachScan?.total ? Math.round((breachScan.checked / breachScan.total) * 100) : 0

  let showAllBreached = false
  $: if (breachScan?.phase !== 'finished') showAllBreached = false
  $: visibleBreached = showAllBreached ? breachedResults : breachedResults.slice(0, DISPLAY_LIMIT)

  function savedLogin(id: string) {
    return snapshot?.entries.find((entry) => entry.id === id)
  }
</script>

{#if duplicateReviewOpen}
  <section class="cleanup-view">
    <div class="cleanup-toolbar"><button type="button" class="text-button" on:click={() => (duplicateReviewOpen = false)}><span aria-hidden="true">←</span> Back to checkup</button><p>Merge only entries that represent the same account.</p></div>
    {#if duplicateReviewLoading}
      <div class="cleanup-loading state-panel" aria-live="polite"><span class="inline-spinner" aria-hidden="true"></span><p>Checking duplicate groups…</p></div>
    {:else}
      <DuplicateReview
        groups={duplicateGroups}
        selectedGroupId={duplicateGroupId}
        selectedEntryIds={duplicateSelectedIds}
        onSelectGroup={onSelectGroup}
        onSelectEntry={onSelectEntry}
        onEdit={onEdit}
        onMerge={onMerge}
        onDelete={onDelete}
      />
    {/if}
  </section>
{:else}
<section class="checkup-view">
  <ViewHeader title={snapshot?.security.needsAttention ? 'Review your vault' : 'No issues found'}>
    <div slot="aside" class="view-header-aside" class:none={goodCount === 0}><strong>{goodCount} of {loginCount}</strong><span>{loginCount === 1 ? 'login in good shape' : 'logins in good shape'}</span></div>
  </ViewHeader>
  <section class="findings-list" aria-label="Security findings">
    {#each actionableFindings as finding (finding.key)}
      {#if finding.onClick}
        <button class="finding-row" class:danger={finding.danger} on:click={finding.onClick}><span class="finding-icon"><Icon name={finding.icon} size={15} /></span><div><h3>{finding.title}</h3><p>{finding.activeText}</p></div><strong>{finding.count}</strong><Icon name="chevron-right" size={18} /></button>
      {:else}
        <div class="finding-row"><span class="finding-icon"><Icon name={finding.icon} size={15} /></span><div><h3>{finding.title}</h3><p>{finding.activeText}</p></div><strong>{finding.count}</strong><span class="finding-chevron-space" aria-hidden="true"></span></div>
      {/if}
      {#if finding.logins?.length}
        <ul class="checkup-logins finding-logins" aria-label={finding.title}>
          {#each finding.logins as login (login.id)}
            <li><button type="button" class="checkup-login" on:click={() => onOpenLogin(login.id)}><span class="entry-avatar checkup-login-avatar"><WebsiteIcon site={login.site} initials={savedLogin(login.id)?.initials ?? login.title.slice(0, 1).toUpperCase()} enabled={siteIconsEnabled} /></span><span class="checkup-login-text"><strong>{login.title}</strong><small>{login.site}</small></span><Icon name="chevron-right" size={15} /></button></li>
          {/each}
          {#if finding.count > finding.logins.length}<li class="checkup-logins-more">and {finding.count - finding.logins.length} more</li>{/if}
        </ul>
      {/if}
    {/each}
    {#if clearFindings.length}
      <details class="clear-findings">
        <summary><Icon name="chevron-right" size={15} /><span>No issues</span><span class="clear-findings-count">{clearFindings.length} {clearFindings.length === 1 ? 'category' : 'categories'} clear</span></summary>
        <ul class="clear-list">
          {#each clearFindings as finding (finding.key)}
            <li class="finding-row clear"><span class="finding-icon"><Icon name={finding.icon} size={15} /></span><div><h3>{finding.title}</h3><p>{finding.clearText}</p></div></li>
          {/each}
        </ul>
      </details>
    {/if}
  </section>

  <section class="breach-check" aria-label="Breach check">
    <div class="breach-check-head">
      <span class="breach-check-icon" class:found={breachedResults.length > 0}><Icon name={breachedResults.length ? 'shield-alert' : 'shield'} size={17} /></span>
      <div>
        <h3>Breach check</h3>
        {#if breachScan?.phase === 'running'}
          <p aria-live="polite">Checked {breachScan.checked} of {breachScan.total} logins. Only five-character hash prefixes leave this device.</p>
        {:else if breachedResults.length}
          <p class="breach-check-found">{breachedResults.length} {breachedResults.length === 1 ? 'password appears' : 'passwords appear'} in known breaches. Replace these first:</p>
        {:else if breachScan?.phase === 'finished' && !unknownResults.length}
          <p>No saved password appears in known breaches.</p>
        {:else if breachScan?.phase === 'cancelled'}
          <p>The check stopped before it finished. Nothing was verified.</p>
        {:else if breachScan?.phase !== 'finished'}
          <p>Not checked yet. Only the first five characters of each password's SHA-1 hash leave this device.</p>
        {/if}
        {#if unknownResults.length}
          <p>{unknownResults.length} {unknownResults.length === 1 ? 'password' : 'passwords'} could not be checked because the service did not answer. Sesame does not know whether {unknownResults.length === 1 ? 'it is' : 'they are'} safe.</p>
        {/if}
      </div>
    </div>
    {#if breachScanError}
      <p class="breach-check-error" role="alert">{breachScanError}</p>
      <button type="button" class="secondary-button" on:click={onStartBreachScan}>Try again</button>
    {:else if breachScan?.phase === 'running'}
      <div class="breach-check-bar" role="progressbar" aria-valuemin="0" aria-valuemax={breachScan.total} aria-valuenow={breachScan.checked}><span style={`width: ${progressPercent}%`}></span></div>
      <button type="button" class="text-button" on:click={onCancelBreachScan}>Cancel</button>
    {:else if breachScan?.phase === 'finished' || breachScan?.phase === 'cancelled'}
      {#if breachedResults.length}
        <ul class="checkup-logins breach-check-list" aria-label="Logins with breached passwords">
          {#each visibleBreached as result (result.id)}
            {@const login = savedLogin(result.id)}
            <li><button type="button" class="checkup-login" disabled={!login} on:click={() => login && onOpenLogin(result.id)}><span class="entry-avatar checkup-login-avatar"><WebsiteIcon site={login?.site ?? ''} initials={login?.initials ?? '?'} enabled={siteIconsEnabled} /></span><span class="checkup-login-text"><strong>{login?.title ?? 'Deleted login'}</strong><small>{login?.site || 'No website saved'}</small></span><Icon name="chevron-right" size={15} /></button></li>
          {/each}
        </ul>
        {#if breachedResults.length > DISPLAY_LIMIT}
          <button type="button" class="text-button breach-check-more" aria-expanded={showAllBreached} on:click={() => (showAllBreached = !showAllBreached)}>{showAllBreached ? 'Show fewer' : `Show all ${breachedResults.length}`}</button>
        {/if}
      {/if}
      <button type="button" class="secondary-button" on:click={onStartBreachScan}>Check again</button>
    {:else}
      <button type="button" class="secondary-button" on:click={onStartBreachScan}>Check saved passwords</button>
    {/if}
  </section>
</section>
{/if}
