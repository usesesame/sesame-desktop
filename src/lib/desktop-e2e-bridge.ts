import { invoke } from '@tauri-apps/api/core'

interface DesktopE2eConfig {
  port: number
  token: string
}

export interface DesktopE2eRequest {
  id: number
  command: string
  args: Record<string, unknown>
}

export interface DesktopE2eResult {
  id: number
  ok: boolean
  value?: unknown
  error?: string
}

export interface WebviewFeatures {
  webgl: boolean
  webgl2: boolean
  audioContext: boolean
  mediaDevices: boolean
  mediaElements: boolean
}

const POLL_DELAY_MS = 25

export function webviewFeatures(): WebviewFeatures {
  const scope = globalThis as Record<string, unknown>
  return {
    webgl: document.createElement('canvas').getContext('webgl') !== null,
    webgl2: document.createElement('canvas').getContext('webgl2') !== null,
    audioContext: typeof scope.AudioContext === 'function',
    mediaDevices: typeof navigator.mediaDevices === 'object' && navigator.mediaDevices !== null,
    mediaElements: typeof document.createElement('video').canPlayType === 'function',
  }
}

const pageCommands = new Map<string, () => unknown>([['desktop_e2e_webview_features', webviewFeatures]])

export async function answer(request: DesktopE2eRequest): Promise<DesktopE2eResult> {
  try {
    const pageCommand = pageCommands.get(request.command)
    return {
      id: request.id,
      ok: true,
      value: pageCommand ? pageCommand() : await invoke(request.command, request.args),
    }
  } catch (error) {
    return {
      id: request.id,
      ok: false,
      error: error instanceof Error ? error.message : String(error),
    }
  }
}

function waitBeforeNextPoll(): Promise<void> {
  return new Promise((resolve) => window.setTimeout(resolve, POLL_DELAY_MS))
}

async function sendResult(endpoint: string, result: DesktopE2eResult): Promise<void> {
  const response = await fetch(`${endpoint}/result`, {
    method: 'POST',
    headers: { 'Content-Type': 'text/plain;charset=UTF-8' },
    body: JSON.stringify(result),
  })
  if (!response.ok) throw new Error('The desktop E2E runner rejected a result.')
}

export async function startDesktopE2eBridge(): Promise<void> {
  const config = await invoke<DesktopE2eConfig>('desktop_e2e_config')
  const endpoint = `http://127.0.0.1:${config.port}/${encodeURIComponent(config.token)}`

  while (true) {
    const response = await fetch(`${endpoint}/next`)
    if (response.status === 204) {
      await waitBeforeNextPoll()
      continue
    }
    if (!response.ok) throw new Error('The desktop E2E runner rejected a poll.')

    const request = (await response.json()) as DesktopE2eRequest
    const result = await answer(request)
    await sendResult(endpoint, result)
  }
}
