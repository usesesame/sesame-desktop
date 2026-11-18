import { writable } from 'svelte/store'
import type { EmailAliasSettingsInput, EmailAliasStatus } from './types'
import { getEmailAliasSettings, removeEmailAliasSettings, saveEmailAliasSettings } from './vault'

export const emailAliases = writable<EmailAliasStatus | null>(null)

let generation = 0

function publish(status: EmailAliasStatus, requested: number): EmailAliasStatus {
  if (requested === generation) emailAliases.set(status)
  return status
}

export async function loadEmailAliases(): Promise<EmailAliasStatus> {
  const requested = generation
  return publish(await getEmailAliasSettings(), requested)
}

export async function refreshEmailAliases(): Promise<void> {
  await loadEmailAliases().catch(() => undefined)
}

async function change(action: () => Promise<EmailAliasStatus>): Promise<EmailAliasStatus> {
  const requested = ++generation
  try {
    const status = publish(await action(), requested)
    if (requested === generation) generation += 1
    return status
  } catch (error) {
    if (requested === generation) {
      generation += 1
      void refreshEmailAliases()
    }
    throw error
  }
}

export function saveEmailAliases(settings: EmailAliasSettingsInput): Promise<EmailAliasStatus> {
  return change(() => saveEmailAliasSettings(settings))
}

export function removeEmailAliases(): Promise<EmailAliasStatus> {
  return change(removeEmailAliasSettings)
}

export function clearEmailAliases(): void {
  generation += 1
  emailAliases.set(null)
}

export const serviceNames = { addy: 'addy.io', simpleLogin: 'SimpleLogin' } as const
