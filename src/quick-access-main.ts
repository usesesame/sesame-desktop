import { mount } from 'svelte'
import '../design/tokens.css'
import './app.css'
import QuickAccessView from './lib/ui/QuickAccessView.svelte'
import { disableDefaultContextMenu } from './lib/production-webview'

if (import.meta.env.PROD) disableDefaultContextMenu()

const app = mount(QuickAccessView, {
  target: document.getElementById('app')!,
})

export default app
