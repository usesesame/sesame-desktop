import { invoke } from '@tauri-apps/api/core'

interface DesktopE2eConfig {
  port: number
  token: string
}

interface DesktopE2eRequest {
  id: number
  command: string
  args: Record<string, unknown>
}

interface DesktopE2eResult {
  id: number
  ok: boolean
  value?: unknown
  error?: string
}

const POLL_DELAY_MS = 25

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
    let result: DesktopE2eResult
    try {
      result = {
        id: request.id,
        ok: true,
        value: await invoke(request.command, request.args),
      }
    } catch (error) {
      result = {
        id: request.id,
        ok: false,
        error: error instanceof Error ? error.message : String(error),
      }
    }
    await sendResult(endpoint, result)
  }
}
