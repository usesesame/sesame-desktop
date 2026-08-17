<script lang="ts">
  import Icon from '../Icon.svelte'
  import DuplicateReview from './DuplicateReview.svelte'
  import { issueKindLabels, issueSeverityWeight } from '../issue-kinds'
  import type { CleanupEntry, DuplicateGroup, IssueKind, VaultSnapshot } from '../types'

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

  type Finding = { kind: IssueKind; icon: string; count: number; activeText: string; clearText: string; onClick: () => void }

  $: findings = ([
    { kind: 'reused-password', icon: 'copy', count: snapshot?.security.reusedPasswords ?? 0, activeText: 'One leaked account could expose another', clearText: 'No reused passwords found', onClick: () => onShowSecurityFilter('reused-password') },
    { kind: 'compromised-pattern', icon: 'shield-alert', count: snapshot?.security.compromisedPatterns ?? 0, activeText: 'Predictable sequences and breached-style patterns', clearText: 'No unsafe password patterns found', onClick: () => onShowSecurityFilter('compromised-pattern') },
    { kind: 'weak-password', icon: 'key', count: snapshot?.security.weakPasswords ?? 0, activeText: 'Short or low-variety passwords to replace', clearText: 'No weak passwords found', onClick: () => onShowSecurityFilter('weak-password') },
    { kind: 'common-password', icon: 'alert', count: snapshot?.security.commonPasswords ?? 0, activeText: 'Passwords attackers are likely to try first', clearText: 'No common passwords found', onClick: () => onShowSecurityFilter('common-password') },
    { kind: 'old-password', icon: 'refresh', count: snapshot?.security.oldPasswords ?? 0, activeText: 'Not changed in over a year', clearText: 'Every password was changed in the last year', onClick: () => onShowSecurityFilter('old-password') },
    { kind: 'totp', icon: 'shield-alert', count: snapshot?.security.noTotp ?? 0, activeText: 'Accounts without a stored code', clearText: 'Every login has 2FA saved', onClick: () => onShowSecurityFilter('totp') },
    { kind: 'recovery', icon: 'file-key', count: snapshot?.security.missingRecovery ?? 0, activeText: 'Logins with no saved recovery option', clearText: "Every login's recovery is reviewed", onClick: () => onShowSecurityFilter('recovery') },
    { kind: 'duplicate', icon: 'copy', count: snapshot?.security.duplicateCandidates ?? 0, activeText: 'Review and merge likely matches', clearText: 'Nothing to merge', onClick: onOpenDuplicateReview },
    { kind: 'url', icon: 'globe', count: snapshot?.security.missingUrls ?? 0, activeText: 'Add the sign-in site to these logins', clearText: 'Every login has a website', onClick: () => onShowSecurityFilter('url') },
  ] as Finding[]).sort((a, b) => {
    if ((a.count > 0) !== (b.count > 0)) return a.count > 0 ? -1 : 1
    return issueSeverityWeight[a.kind] - issueSeverityWeight[b.kind]
  })
</script>

{#if duplicateReviewOpen}
  <section class="cleanup-view">
    <div class="cleanup-toolbar"><button type="button" class="text-button" on:click={() => (duplicateReviewOpen = false)}><span aria-hidden="true">←</span> Back to checkup</button><p>Merge only entries that represent the same account.</p></div>
    {#if duplicateReviewLoading}
      <div class="cleanup-loading" aria-live="polite"><span class="inline-spinner" aria-hidden="true"></span><p>Checking duplicate groups…</p></div>
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
  <header class="view-header">
    <div><h2>{snapshot?.security.needsAttention ? 'Review your vault' : 'No issues found'}</h2><p>These checks run while the vault is open. Nothing leaves this device.</p></div>
    <div class="view-header-aside"><strong>{snapshot?.security.good ?? 0}</strong><span>accounts ready</span></div>
  </header>
  <section class="findings-list" aria-label="Security findings">
    {#each findings as finding (finding.kind)}
      <button class="finding-row" class:clear={finding.count === 0} disabled={finding.count === 0} on:click={finding.onClick}><span class="finding-icon"><Icon name={finding.icon} size={17} /></span><div><h3>{issueKindLabels[finding.kind].title}</h3><p>{finding.count ? finding.activeText : finding.clearText}</p></div><strong>{finding.count}</strong><Icon name="chevron-right" size={18} /></button>
    {/each}
  </section>
  <div class="privacy-callout"><span><Icon name="shield" size={16} /></span><div><strong>This checkup stays on your device.</strong><p>Passwords are compared only while your vault is unlocked.</p></div></div>
</section>
{/if}
