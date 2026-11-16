<script lang="ts">
  import Icon from '../Icon.svelte'
  import { isKeptField, type DraftField } from '../kept-secrets'

  export let fields: DraftField[] = []
  export let onChange: (fields: DraftField[]) => void

  function update(index: number, patch: Partial<DraftField>) {
    onChange(fields.map((field, current) => (current === index ? { ...field, ...patch } : field)))
  }

  function add() {
    onChange([...fields, { label: '', value: '', kind: 'text' }])
  }

  function remove(index: number) {
    onChange(fields.filter((_, current) => current !== index))
  }

  function dropsKeptValue(field: DraftField): boolean {
    return field.keptFrom !== undefined && field.kind !== 'secret' && !field.value
  }
</script>

<section class="editor-section login-fields-editor" aria-labelledby="login-fields-heading">
  <div><h3 id="login-fields-heading">Custom fields</h3><p>A hidden value stays masked until you reveal it, and a saved one stays unless you type a new value.</p></div>
  {#each fields as field, index (index)}
    <div class="login-field">
    <div class="login-field-row">
      <input
        class="custom-field-label login-field-name"
        value={field.label}
        on:input={(event) => update(index, { label: event.currentTarget.value })}
        maxlength="160"
        placeholder="Name"
        autocomplete="off"
        spellcheck="false"
        aria-label={`Field ${index + 1} name`}
      />
      <input
        class="custom-field-value login-field-value"
        value={field.value}
        on:input={(event) => update(index, { value: event.currentTarget.value })}
        maxlength="20000"
        placeholder={isKeptField(field) ? 'Saved value kept' : 'Value'}
        type={field.kind === 'secret' ? 'password' : 'text'}
        autocomplete="off"
        spellcheck="false"
        aria-label={`Field ${index + 1} value`}
      />
      <button
        type="button"
        class="login-field-hidden"
        role="switch"
        aria-checked={field.kind === 'secret'}
        aria-label={`Field ${index + 1} hidden`}
        on:click={() => update(index, { kind: field.kind === 'secret' ? 'text' : 'secret' })}
      ><span class="switch" class:active={field.kind === 'secret'} aria-hidden="true"><span></span></span><span aria-hidden="true">Hidden</span></button>
      <button type="button" class="icon-button login-field-remove" aria-label={`Remove field ${index + 1}`} title={`Remove field ${index + 1}`} on:click={() => remove(index)}><Icon name="trash" size={14} /></button>
    </div>
    {#if isKeptField(field)}
      <p class="field-hint login-field-hint"><button type="button" class="text-button" on:click={() => update(index, { keptFrom: undefined })}>Remove saved value</button></p>
    {:else if dropsKeptValue(field)}
      <p class="field-hint login-field-hint">The saved hidden value is removed when you save. Type it again to keep it.</p>
    {/if}
    </div>
  {/each}
  <button type="button" class="secondary-button login-field-add" on:click={add}><Icon name="plus" size={14} /><span>Add field</span></button>
</section>

<style>
  .login-fields-editor { gap: var(--space-2); }
  .login-fields-editor > div:first-child { margin-bottom: var(--space-1); }
  .login-field-row { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1.4fr) auto auto; gap: var(--space-2); align-items: center; }
  .login-field-hidden { display: inline-flex; align-items: center; gap: var(--space-2); border: 0; padding: 0 var(--space-1); color: var(--text-2); background: transparent; font-size: var(--type-2); font-weight: var(--weight-bold); cursor: pointer; }
  .login-field-hidden:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; border-radius: var(--radius-sm); }
  .login-field { display: grid; gap: var(--space-2); }
  .login-field-hint { margin: 0; }
  .login-field-add { justify-self: start; margin-top: var(--space-1); }
  @media (max-width: 680px) {
    .login-field { padding-bottom: var(--space-3); border-bottom: 1px solid var(--border-soft); }
    .login-field-row { grid-template-columns: minmax(0, 1fr) auto; grid-template-areas: "name remove" "value hidden"; }
    .login-field-name { grid-area: name; }
    .login-field-value { grid-area: value; }
    .login-field-hidden { grid-area: hidden; }
    .login-field-remove { grid-area: remove; justify-self: end; }
  }
</style>
