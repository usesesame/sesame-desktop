<script lang="ts">
  import Icon from '../Icon.svelte'
  import DuplicateReview from './DuplicateReview.svelte'
  import ViewHeader from './ViewHeader.svelte'
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

  $: goodCount = snapshot?.security.good ?? 0

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
  ] as Finding[]).sort((a, b) => issueSeverityWeight[a.kind] - issueSeverityWeight[b.kind])

  $: actionableFindings = findings.filter((finding) => finding.count > 0)
  $: clearFindings = findings.filter((finding) => finding.count === 0)
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
    <div slot="aside" class="view-header-aside"><strong>{goodCount}</strong><span>{goodCount === 1 ? 'account ready' : 'accounts ready'}</span></div>
  </ViewHeader>
  <section class="findings-list" aria-label="Security findings">
    {#each actionableFindings as finding (finding.kind)}
      <button class="finding-row" on:click={finding.onClick}><span class="finding-icon"><Icon name={finding.icon} size={15} /></span><div><h3>{issueKindLabels[finding.kind].title}</h3><p>{finding.activeText}</p></div><strong>{finding.count}</strong><Icon name="chevron-right" size={18} /></button>
    {/each}
    {#if clearFindings.length}
      <details class="clear-findings">
        <summary><Icon name="chevron-right" size={15} /><span>No issues</span><span class="clear-findings-count">{clearFindings.length} {clearFindings.length === 1 ? 'category' : 'categories'} clear</span></summary>
        <ul class="clear-list">
          {#each clearFindings as finding (finding.kind)}
            <li class="finding-row clear"><span class="finding-icon"><Icon name={finding.icon} size={15} /></span><div><h3>{issueKindLabels[finding.kind].title}</h3><p>{finding.clearText}</p></div></li>
          {/each}
        </ul>
      </details>
    {/if}
  </section>
</section>
{/if}
