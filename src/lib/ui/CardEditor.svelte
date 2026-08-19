<script lang="ts">
  import ModalShell from './ModalShell.svelte'
  import LegacyDataPanel from './LegacyDataPanel.svelte'
  import type { CardInput, LegacyField } from '../types'

  export let cardDraft: CardInput
  export let editorTitle = 'Add a card'
  export let savingCard = false
  export let loadingCard = false
  export let legacyFields: LegacyField[] = []
  export let onSubmit: () => void
  export let onClose: () => void

  let titleInput: HTMLInputElement

  // Tracked from input events, not a snapshot, so nothing holds a second copy of the record.
  let dirty = false
  let confirmingDiscard = false

  function requestClose() {
    if (savingCard) return
    if (dirty) {
      confirmingDiscard = true
      return
    }
    onClose()
  }

  function discard() {
    confirmingDiscard = false
    dirty = false
    onClose()
  }

  function focusInitial() {
    titleInput?.focus()
  }

  // Issuer identification numbers, longest prefix first so 34/37 beat 3.
  const networks: Array<{ name: string; test: RegExp; groups: number[]; csc: number }> = [
    { name: 'American Express', test: /^3[47]/, groups: [4, 6, 5], csc: 4 },
    { name: 'Diners Club', test: /^3(?:0[0-5]|[689])/, groups: [4, 6, 4], csc: 3 },
    { name: 'Visa', test: /^4/, groups: [4, 4, 4, 4], csc: 3 },
    { name: 'Mastercard', test: /^(?:5[1-5]|2[2-7])/, groups: [4, 4, 4, 4], csc: 3 },
    { name: 'Discover', test: /^6(?:011|5|4[4-9])/, groups: [4, 4, 4, 4], csc: 3 },
    { name: 'JCB', test: /^35(?:2[89]|[3-8])/, groups: [4, 4, 4, 4], csc: 3 },
    { name: 'UnionPay', test: /^62/, groups: [4, 4, 4, 4], csc: 3 },
  ]

  function digitsOf(value: string): string {
    return value.replace(/\D/g, '')
  }

  function networkFor(digits: string) {
    return networks.find((network) => network.test.test(digits))
  }

  function groupNumber(digits: string): string {
    const groups = networkFor(digits)?.groups ?? [4, 4, 4, 4, 4]
    const parts: string[] = []
    let index = 0
    for (const size of groups) {
      if (index >= digits.length) break
      parts.push(digits.slice(index, index + size))
      index += size
    }
    if (index < digits.length) parts.push(digits.slice(index))
    return parts.join(' ')
  }

  // A single mistyped digit fails this, which is the point: it is a typo check,
  // not a statement about whether the card is real, so it warns and never blocks.
  function passesLuhn(digits: string): boolean {
    let sum = 0
    let double = false
    for (let index = digits.length - 1; index >= 0; index -= 1) {
      let value = Number(digits[index])
      if (double) {
        value *= 2
        if (value > 9) value -= 9
      }
      sum += value
      double = !double
    }
    return digits.length > 0 && sum % 10 === 0
  }

  function onNumberInput(event: Event) {
    const field = event.currentTarget as HTMLInputElement
    const digits = digitsOf(field.value).slice(0, 19)
    cardDraft = { ...cardDraft, number: digits }
    field.value = groupNumber(digits)
    // Only ever fills a blank, so a network typed by hand is never overwritten.
    const detected = networkFor(digits)?.name
    if (detected && !cardDraft.brand.trim()) cardDraft = { ...cardDraft, brand: detected }
  }

  function onMonthInput(event: Event) {
    const field = event.currentTarget as HTMLInputElement
    let month = digitsOf(field.value).slice(0, 2)
    // A lone 2 through 9 can only be a single-digit month, so pad it.
    if (month.length === 1 && Number(month) > 1) month = `0${month}`
    field.value = month
    cardDraft = { ...cardDraft, expiryMonth: month }
  }

  function onYearInput(event: Event) {
    const field = event.currentTarget as HTMLInputElement
    const year = digitsOf(field.value).slice(0, 4)
    field.value = year
    cardDraft = { ...cardDraft, expiryYear: year }
  }

  $: numberDigits = digitsOf(cardDraft.number ?? '')
  $: network = networkFor(numberDigits)
  $: numberLooksMistyped = numberDigits.length >= 12 && !passesLuhn(numberDigits)
  $: monthValue = Number(cardDraft.expiryMonth)
  $: monthOutOfRange = (cardDraft.expiryMonth ?? '').length > 0 && (!Number.isInteger(monthValue) || monthValue < 1 || monthValue > 12)
  $: cscExpected = network?.csc ?? 0
  $: cscUnexpectedLength =
    cscExpected > 0 &&
    (cardDraft.securityCode ?? '').length > 0 &&
    digitsOf(cardDraft.securityCode).length !== cscExpected
  $: expired = expiryHasPassed(cardDraft.expiryMonth, cardDraft.expiryYear)

  function expiryHasPassed(month: string, year: string): boolean {
    const monthNumber = Number(month)
    const yearNumber = Number(year)
    if (!monthNumber || monthNumber < 1 || monthNumber > 12) return false
    if (!yearNumber || String(year).length !== 4) return false
    const now = new Date()
    // A card is valid through the last day of its expiry month.
    return yearNumber < now.getFullYear() || (yearNumber === now.getFullYear() && monthNumber < now.getMonth() + 1)
  }
</script>

<ModalShell
  open={true}
  onClose={requestClose}
  labelledby="card-editor-heading"
  tone="editor"
  modalClass="login-editor"
  initialFocus={focusInitial}
  ariaBusy={savingCard || loadingCard}
>
  <form on:submit|preventDefault={onSubmit} on:input={() => (dirty = true)}>
  <header class="editor-header">
    <div><p class="eyebrow">{cardDraft.id ? 'Saved card' : 'New card'}</p><h2 id="card-editor-heading">{editorTitle}</h2></div>
    <button class="modal-close" type="button" disabled={savingCard} on:click={requestClose} aria-label="Close card editor">×</button>
  </header>

  <div class="editor-fields">
    <label>Name <span class="field-hint">How this card appears in your list, e.g. "Everyday card"</span><input bind:this={titleInput} bind:value={cardDraft.title} required maxlength="160" placeholder="e.g. Everyday card" autocomplete="off" /></label>
    <label>Cardholder name<input bind:value={cardDraft.cardholderName} maxlength="256" autocomplete="cc-name" /></label>
    <label>Card number
      {#if network}<span class="field-hint">{network.name}</span>{/if}
      <input value={groupNumber(numberDigits)} on:input={onNumberInput} maxlength="24" inputmode="numeric" autocomplete="cc-number" placeholder="e.g. 4242 4242 4242 4242" />
      {#if numberLooksMistyped}<span class="field-warning">Check this number. A digit looks mistyped.</span>{/if}
    </label>
    <div class="editor-two-column">
      <label>Expiry month <span class="field-hint">MM</span>
        <input value={cardDraft.expiryMonth} on:input={onMonthInput} maxlength="2" inputmode="numeric" autocomplete="cc-exp-month" placeholder="09" />
        {#if monthOutOfRange}<span class="field-warning">A month runs from 01 to 12.</span>{/if}
      </label>
      <label>Expiry year <span class="field-hint">YYYY</span>
        <input value={cardDraft.expiryYear} on:input={onYearInput} maxlength="4" inputmode="numeric" autocomplete="cc-exp-year" placeholder="2030" />
        {#if expired}<span class="field-warning">This card expired.</span>{/if}
      </label>
    </div>
    <div class="editor-two-column">
      <label>Security code {#if cscExpected}<span class="field-hint">{cscExpected} digits</span>{/if}
        <input bind:value={cardDraft.securityCode} maxlength="4" inputmode="numeric" autocomplete="cc-csc" />
        {#if cscUnexpectedLength}<span class="field-warning">{network?.name} uses {cscExpected} digits.</span>{/if}
      </label>
      <label>Network <span class="field-hint">Filled from the card number</span><input bind:value={cardDraft.brand} maxlength="64" autocomplete="cc-type" /></label>
    </div>
    <label>Notes<textarea bind:value={cardDraft.notes} rows="4" maxlength="4000"></textarea></label>
    <label>Tags <span class="field-hint">Comma separated, optional</span><input value={cardDraft.tags.join(', ')} on:input={(event) => (cardDraft = { ...cardDraft, tags: event.currentTarget.value.split(',').map((value) => value.trim()).filter(Boolean) })} maxlength="500" autocomplete="off" placeholder="e.g. personal, travel" /></label>
    <LegacyDataPanel fields={legacyFields} />
  </div>

  {#if confirmingDiscard}
    <footer class="editor-footer discard-confirm">
      <p><strong>Discard your changes?</strong> This card has edits that have not been saved.</p>
      <div class="editor-footer-actions">
        <button type="button" class="secondary-button" on:click={() => (confirmingDiscard = false)}>Keep editing</button>
        <button type="button" class="editor-delete" on:click={discard}>Discard changes</button>
      </div>
    </footer>
  {:else}
    <footer class="editor-footer"><div class="editor-footer-actions"><button type="button" class="secondary-button" disabled={savingCard} on:click={requestClose}>Cancel</button><button class="primary-button" type="submit" disabled={savingCard || loadingCard}>{savingCard ? 'Saving…' : 'Save card'}</button></div></footer>
  {/if}
  </form>
</ModalShell>
