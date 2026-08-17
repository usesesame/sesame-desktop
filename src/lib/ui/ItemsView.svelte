<script lang="ts">
  import { onMount, tick } from 'svelte'
  import Icon from '../Icon.svelte'
  import type { VaultSnapshot } from '../types'
  import type { IdentityController } from '../controllers/identity-controller'
  import type { SecureNoteController } from '../controllers/secure-note-controller'
  import type { CardController } from '../controllers/card-controller'
  import type { WifiNetworkController } from '../controllers/wifi-network-controller'
  import type { SshKeyController } from '../controllers/ssh-key-controller'
  import type { SoftwareLicenseController } from '../controllers/software-license-controller'
  import type { DocumentController } from '../controllers/document-controller'
  import type { CustomRecordController } from '../controllers/custom-record-controller'
  import type { TrashController } from '../controllers/trash-controller'
  import type { HistoryController } from '../controllers/history-controller'
  import IdentitiesView from './IdentitiesView.svelte'
  import SecureNotesView from './SecureNotesView.svelte'
  import CardsView from './CardsView.svelte'
  import WifiNetworksView from './WifiNetworksView.svelte'
  import SshKeysView from './SshKeysView.svelte'
  import SoftwareLicensesView from './SoftwareLicensesView.svelte'
  import DocumentsView from './DocumentsView.svelte'
  import CustomRecordsView from './CustomRecordsView.svelte'
  import TrashView from './TrashView.svelte'
  import HistoryView from './HistoryView.svelte'

  export let snapshot: VaultSnapshot | null
  export let identityController: IdentityController
  export let secureNoteController: SecureNoteController
  export let cardController: CardController
  export let wifiNetworkController: WifiNetworkController
  export let sshKeyController: SshKeyController
  export let softwareLicenseController: SoftwareLicenseController
  export let documentController: DocumentController
  export let customRecordController: CustomRecordController
  export let trashController: TrashController
  export let historyController: HistoryController
  const trashState = trashController.state
  const historyState = historyController.state

  type ItemTabId = 'identities' | 'secure-notes' | 'cards' | 'wifi-networks' | 'ssh-keys' | 'software-licenses' | 'documents' | 'custom-records' | 'trash' | 'history'
  const tabs: { id: ItemTabId; label: string; icon: string }[] = [
    { id: 'identities', label: 'Identities', icon: 'user' },
    { id: 'secure-notes', label: 'Secure notes', icon: 'note' },
    { id: 'cards', label: 'Cards', icon: 'card' },
    { id: 'wifi-networks', label: 'Wi-Fi networks', icon: 'wifi' },
    { id: 'ssh-keys', label: 'SSH keys', icon: 'key' },
    { id: 'software-licenses', label: 'Software licences', icon: 'license' },
    { id: 'documents', label: 'Documents', icon: 'id-card' },
    { id: 'custom-records', label: 'Custom records', icon: 'custom' },
    { id: 'trash', label: 'Trash', icon: 'trash' },
    { id: 'history', label: 'History', icon: 'refresh' },
  ]
  export let tab: ItemTabId = 'identities'
  const tabButtons: HTMLButtonElement[] = []
  let tabStrip: HTMLDivElement
  let tabsAtStart = true
  let tabsAtEnd = true

  function updateTabScrollState() {
    if (!tabStrip) return
    const lastScrollPosition = Math.max(0, tabStrip.scrollWidth - tabStrip.clientWidth)
    tabsAtStart = tabStrip.scrollLeft <= 1
    tabsAtEnd = tabStrip.scrollLeft >= lastScrollPosition - 1
  }

  function scrollTabs(direction: -1 | 1) {
    tabStrip?.scrollBy({
      left: Math.max(220, tabStrip.clientWidth * 0.72) * direction,
      behavior: 'smooth',
    })
  }

  function keepTabVisible(index: number) {
    const button = tabButtons[index]
    if (!button || !tabStrip) return
    const buttonLeft = button.offsetLeft
    const buttonRight = buttonLeft + button.offsetWidth
    const visibleLeft = tabStrip.scrollLeft
    const visibleRight = visibleLeft + tabStrip.clientWidth
    if (buttonLeft < visibleLeft) tabStrip.scrollTo({ left: buttonLeft - 3, behavior: 'smooth' })
    else if (buttonRight > visibleRight) tabStrip.scrollTo({ left: buttonRight - tabStrip.clientWidth + 3, behavior: 'smooth' })
  }

  async function selectTab(nextTab: ItemTabId, index: number) {
    tab = nextTab
    await tick()
    keepTabVisible(index)
  }

  onMount(() => {
    updateTabScrollState()
    if (typeof ResizeObserver === 'undefined') return
    const observer = new ResizeObserver(updateTabScrollState)
    observer.observe(tabStrip)
    return () => observer.disconnect()
  })

  function historyItemTitle(kind: string, itemId: string): string | null {
    switch (kind) {
      case 'login':
        return snapshot?.entries.find((entry) => entry.id === itemId)?.title ?? null
      case 'identity':
        return snapshot?.identities.find((entry) => entry.id === itemId)?.label ?? null
      case 'secure_note':
        return snapshot?.secureNotes.find((entry) => entry.id === itemId)?.title ?? null
      case 'card':
        return snapshot?.cards.find((entry) => entry.id === itemId)?.title ?? null
      case 'wifi_network':
        return snapshot?.wifiNetworks.find((entry) => entry.id === itemId)?.title ?? null
      case 'ssh_key':
        return snapshot?.sshKeys.find((entry) => entry.id === itemId)?.title ?? null
      case 'software_license':
        return snapshot?.softwareLicenses.find((entry) => entry.id === itemId)?.title ?? null
      case 'document':
        return snapshot?.documents.find((entry) => entry.id === itemId)?.title ?? null
      case 'custom_record':
        return snapshot?.customRecords.find((entry) => entry.id === itemId)?.title ?? null
      default:
        return null
    }
  }

  async function handleTabKeydown(event: KeyboardEvent, index: number) {
    let nextIndex: number | null = null
    if (event.key === 'ArrowRight' || event.key === 'ArrowDown') nextIndex = (index + 1) % tabs.length
    if (event.key === 'ArrowLeft' || event.key === 'ArrowUp') nextIndex = (index - 1 + tabs.length) % tabs.length
    if (event.key === 'Home') nextIndex = 0
    if (event.key === 'End') nextIndex = tabs.length - 1
    if (nextIndex === null) return

    event.preventDefault()
    await selectTab(tabs[nextIndex].id, nextIndex)
    tabButtons[nextIndex]?.focus()
  }
</script>

<section class="items-view">
  <div class="items-tab-navigation">
    <button type="button" class="items-tab-scroll" aria-label="Show previous item types" title="Previous item types" disabled={tabsAtStart} on:click={() => scrollTabs(-1)}><Icon name="chevron-left" size={15} /></button>
    <div bind:this={tabStrip} class="settings-tabs items-tabs" role="tablist" aria-label="Item type" on:scroll={updateTabScrollState}>
      {#each tabs as item, index (item.id)}
        <button
          bind:this={tabButtons[index]}
          id={`items-tab-${item.id}`}
          role="tab"
          type="button"
          class:active={tab === item.id}
          aria-selected={tab === item.id}
          aria-controls={`items-panel-${item.id}`}
          tabindex={tab === item.id ? 0 : -1}
          on:click={() => void selectTab(item.id, index)}
          on:keydown={(event) => handleTabKeydown(event, index)}
        >
          <Icon name={item.icon} size={15} strokeWidth={1.9} />{item.label}
        </button>
      {/each}
    </div>
    <button type="button" class="items-tab-scroll" aria-label="Show next item types" title="Next item types" disabled={tabsAtEnd} on:click={() => scrollTabs(1)}><Icon name="chevron-right" size={15} /></button>
  </div>

  <div id={`items-panel-${tab}`} class="settings-panel" role="tabpanel" aria-labelledby={`items-tab-${tab}`}>
    {#key tab}
      {#if tab === 'identities'}
        <IdentitiesView identities={snapshot?.identities ?? []} onAdd={identityController.openNew} onEdit={(id) => void identityController.openEditor(id)} onDelete={identityController.requestDelete} />
      {:else if tab === 'secure-notes'}
        <SecureNotesView notes={snapshot?.secureNotes ?? []} onAdd={secureNoteController.openNew} onEdit={(id) => void secureNoteController.openEditor(id)} onDelete={secureNoteController.requestDelete} />
      {:else if tab === 'cards'}
        <CardsView cards={snapshot?.cards ?? []} onAdd={cardController.openNew} onEdit={(id) => void cardController.openEditor(id)} onDelete={cardController.requestDelete} />
      {:else if tab === 'wifi-networks'}
        <WifiNetworksView networks={snapshot?.wifiNetworks ?? []} onAdd={wifiNetworkController.openNew} onEdit={(id) => void wifiNetworkController.openEditor(id)} onDelete={wifiNetworkController.requestDelete} />
      {:else if tab === 'ssh-keys'}
        <SshKeysView keys={snapshot?.sshKeys ?? []} onAdd={sshKeyController.openNew} onEdit={(id) => void sshKeyController.openEditor(id)} onDelete={sshKeyController.requestDelete} />
      {:else if tab === 'software-licenses'}
        <SoftwareLicensesView licenses={snapshot?.softwareLicenses ?? []} onAdd={softwareLicenseController.openNew} onEdit={(id) => void softwareLicenseController.openEditor(id)} onDelete={softwareLicenseController.requestDelete} />
      {:else if tab === 'documents'}
        <DocumentsView documents={snapshot?.documents ?? []} onAdd={documentController.openNew} onEdit={(id) => void documentController.openEditor(id)} onDelete={documentController.requestDelete} />
      {:else if tab === 'custom-records'}
        <CustomRecordsView records={snapshot?.customRecords ?? []} onAdd={customRecordController.openNew} onEdit={(id) => void customRecordController.openEditor(id)} onDelete={customRecordController.requestDelete} />
      {:else if tab === 'trash'}
        <TrashView
          items={snapshot?.trash ?? []}
          restoringId={$trashState.restoringId}
          previewingId={$trashState.previewingId}
          previewId={$trashState.previewId}
          preview={$trashState.preview}
          onPreview={(id) => void trashController.preview(id)}
          onCancelPreview={trashController.cancelPreview}
          onRestore={(id) => void trashController.restore(id)}
        />
      {:else}
        <HistoryView
          items={snapshot?.history ?? []}
          restoringId={$historyState.restoringId}
          previewingId={$historyState.previewingId}
          previewId={$historyState.previewId}
          preview={$historyState.preview}
          onPreview={(id) => void historyController.preview(id)}
          onCancelPreview={historyController.cancelPreview}
          onRestore={(id) => void historyController.restore(id)}
          titleFor={historyItemTitle}
        />
      {/if}
    {/key}
  </div>
</section>
