import { mount } from 'svelte'
import '../design/tokens.css'
import './app.css'
import App from './App.svelte'
import { disableDefaultContextMenu } from './lib/production-webview'

if (import.meta.env.PROD) disableDefaultContextMenu()

const app = mount(App, {
  target: document.getElementById('app')!,
})

if (import.meta.env.VITE_SESAME_WDIO === 'true') {
  void import('./lib/desktop-e2e-bridge')
    .then(({ startDesktopE2eBridge }) => startDesktopE2eBridge())
    .catch(() => undefined)
}

export default app
