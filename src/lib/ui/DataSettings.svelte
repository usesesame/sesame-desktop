<script lang="ts">
  import Icon from '../Icon.svelte'
  import SyncVaultStorageRow from './SyncVaultStorageRow.svelte'
  import type { DiagnosticStatus } from '../types'

  export let onManageData: () => void
  export let diagnosticEventCount = 0
  export let diagnosticErrorCount = 0
  export let diagnosticWorking = false
  export let diagnosticStatus: DiagnosticStatus = { exists: false, eventCount: 0, errorCount: 0, sizeBytes: 0, localOnly: true, byOperation: [], byCode: [], recent: [] }
  export let onExportDiagnostics: () => void
  export let onClearDiagnostics: () => void

  function diagnosticTime(timestamp: number): string {
    return new Date(timestamp * 1000).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
  }
</script>

<div class="settings-groups">
  <section class="settings-group" aria-labelledby="settings-group-data-vault">
    <h3 id="settings-group-data-vault">Your vault</h3>
    <div class="settings-list">
      <SyncVaultStorageRow />
      <article>
        <div class="setting-copy"><strong>Export and deletion</strong><p>Export a readable copy or remove Sesame data from this device.</p></div>
        <button type="button" class="secondary-button settings-manage" on:click={onManageData}>Manage</button>
      </article>
    </div>
  </section>
  <section class="settings-group" aria-labelledby="settings-group-data-diagnostics">
    <h3 id="settings-group-data-diagnostics">Diagnostics</h3>
    <div class="settings-list">
      <article class="settings-row-expandable">
        <div class="setting-copy"><strong>Local diagnostics</strong><p>{diagnosticEventCount} {diagnosticEventCount === 1 ? 'event' : 'events'} stored, {diagnosticErrorCount} flagged. Routine events clear after a day; flagged ones are kept for support. Events record categories and timing only, never vault contents or raw errors.</p></div>
        <div class="diagnostic-actions"><button type="button" class="secondary-button settings-manage" on:click={onExportDiagnostics} disabled={diagnosticWorking || diagnosticEventCount === 0}>Export</button><button type="button" class="text-button" on:click={onClearDiagnostics} disabled={diagnosticWorking || diagnosticEventCount === 0}>Clear</button></div>
        {#if diagnosticStatus.recent.length > 0}
          <details class="diagnostics-detail">
            <summary><Icon name="chevron-right" size={14} />Recent activity</summary>
            <div class="diagnostics-columns">
            {#if diagnosticStatus.byOperation.length > 0}
              <div class="diagnostics-breakdown">
                <strong>By area</strong>
                <ul>
                  {#each diagnosticStatus.byOperation as entry, i (i)}
                    <li><span>{entry.operation}</span><small>{entry.count} event{entry.count === 1 ? '' : 's'}{entry.errorCount > 0 ? ` · ${entry.errorCount} flagged` : ''}</small></li>
                  {/each}
                </ul>
              </div>
            {/if}
            {#if diagnosticStatus.byCode.length > 0}
              <div class="diagnostics-breakdown">
                <strong>Codes</strong>
                <ul>
                  {#each diagnosticStatus.byCode as entry, i (i)}
                    <li><span class="diagnostic-code" class:error={entry.level === 'error'} class:warn={entry.level === 'warn'}>{entry.code}</span><small>{entry.count} {entry.count === 1 ? 'time' : 'times'}</small></li>
                  {/each}
                </ul>
              </div>
            {/if}
            </div>
            <div class="diagnostics-breakdown">
              <strong>Recent events</strong>
              <ul>
                {#each diagnosticStatus.recent as event, i (i)}
                  <li><span class="diagnostic-code" class:error={event.level === 'error'} class:warn={event.level === 'warn'}>{event.code}</span><small>{event.operation} · {diagnosticTime(event.timestamp)}</small></li>
                {/each}
              </ul>
            </div>
            <p class="tiny-note">Each launch gets one random session id, which groups these events in the exported file. Codes and categories only, never vault contents.</p>
          </details>
        {/if}
      </article>
    </div>
  </section>
</div>
