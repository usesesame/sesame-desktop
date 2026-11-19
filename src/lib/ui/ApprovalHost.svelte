<script lang="ts">
  import type { TerminalApprovalController } from '../controllers/terminal-approval-controller'
  import { useAppStores } from '../stores/app-stores'
  import BrowserCardFillApprovalModal from './BrowserCardFillApprovalModal.svelte'
  import BrowserChangeApprovalModal from './BrowserChangeApprovalModal.svelte'
  import BrowserCreateApprovalModal from './BrowserCreateApprovalModal.svelte'
  import BrowserFillApprovalModal from './BrowserFillApprovalModal.svelte'
  import BrowserIdentityFillApprovalModal from './BrowserIdentityFillApprovalModal.svelte'
  import BrowserSaveApprovalModal from './BrowserSaveApprovalModal.svelte'
  import BrowserTotpFillApprovalModal from './BrowserTotpFillApprovalModal.svelte'
  import TerminalApprovalModal from './TerminalApprovalModal.svelte'

  type Resolves<T> = { resolve: (choice: T) => Promise<void> }

  export let fill: Resolves<string | null>
  export let identity: Resolves<string | null>
  export let card: Resolves<string | null>
  export let totp: Resolves<string | null>
  export let save: Resolves<boolean> & { neverForSite: () => Promise<void> }
  export let change: Resolves<string | null>
  export let create: Resolves<boolean>
  export let terminal: Pick<TerminalApprovalController, 'allow' | 'deny' | 'dismiss' | 'expire' | 'select' | 'setAllowTerminal' | 'setSecret'>

  const { browserFill, browserIdentityFill, browserCardFill, browserTotpFill, browserSave, browserChange, browserCreate, terminalApproval } = useAppStores()
</script>

{#if $browserFill.request}
  {#key $browserFill.request.approvalId}
    <BrowserFillApprovalModal request={$browserFill.request} working={$browserFill.working} onCancel={() => void fill.resolve(null)} onConfirm={() => void fill.resolve($browserFill.selectedId)} />
  {/key}
{:else if $browserIdentityFill.request}
  {#key $browserIdentityFill.request.approvalId}
    <BrowserIdentityFillApprovalModal request={$browserIdentityFill.request} working={$browserIdentityFill.working} onCancel={() => void identity.resolve(null)} onConfirm={() => void identity.resolve($browserIdentityFill.selectedId)} />
  {/key}
{:else if $browserCardFill.request}
  {#key $browserCardFill.request.approvalId}
    <BrowserCardFillApprovalModal request={$browserCardFill.request} working={$browserCardFill.working} onCancel={() => void card.resolve(null)} onConfirm={() => void card.resolve($browserCardFill.selectedId)} />
  {/key}
{:else if $browserTotpFill.request}
  {#key $browserTotpFill.request.approvalId}
    <BrowserTotpFillApprovalModal request={$browserTotpFill.request} working={$browserTotpFill.working} onCancel={() => void totp.resolve(null)} onConfirm={() => void totp.resolve($browserTotpFill.selectedId)} />
  {/key}
{:else if $browserSave.request}
  {#key $browserSave.request.approvalId}
    <BrowserSaveApprovalModal request={$browserSave.request} working={$browserSave.working} onCancel={() => void save.resolve(false)} onConfirm={() => void save.resolve(true)} onNeverForSite={() => void save.neverForSite()} />
  {/key}
{:else if $browserChange.request}
  {#key $browserChange.request.approvalId}
    <BrowserChangeApprovalModal request={$browserChange.request} working={$browserChange.working} onCancel={() => void change.resolve(null)} onConfirm={() => void change.resolve($browserChange.selectedId)} />
  {/key}
{:else if $browserCreate.request}
  {#key $browserCreate.request.approvalId}
    <BrowserCreateApprovalModal request={$browserCreate.request} working={$browserCreate.working} onCancel={() => void create.resolve(false)} onConfirm={() => void create.resolve(true)} />
  {/key}
{:else if $terminalApproval.request}
  {#key $terminalApproval.request.approvalId}
    <TerminalApprovalModal
      request={$terminalApproval.request}
      onAllow={() => void terminal.allow()}
      onDeny={() => void terminal.deny()}
      onDismiss={() => void terminal.dismiss()}
      onExpire={terminal.expire}
      onSelect={terminal.select}
      onAllowTerminal={terminal.setAllowTerminal}
      onSecret={terminal.setSecret}
    />
  {/key}
{/if}
