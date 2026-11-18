<script lang="ts">
  import EmailAliasesSetting from './EmailAliasesSetting.svelte'
  import TerminalAccessSetting from './TerminalAccessSetting.svelte'
</script>

<div class="settings-groups">
  <section class="settings-group" aria-labelledby="settings-group-extras-aliases">
    <h3 id="settings-group-extras-aliases">Email aliases</h3>
    <EmailAliasesSetting />
  </section>
  <section class="settings-group" aria-labelledby="settings-group-extras-command-line">
    <h3 id="settings-group-extras-command-line">Command line</h3>
    <TerminalAccessSetting />
  </section>
</div>
