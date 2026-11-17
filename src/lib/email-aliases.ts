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

export async function saveEmailAliases(settings: EmailAliasSettingsInput): Promise<EmailAliasStatus> {
  const requested = generation
  return publish(await saveEmailAliasSettings(settings), requested)
}

export async function removeEmailAliases(): Promise<EmailAliasStatus> {
  const requested = generation
  return publish(await removeEmailAliasSettings(), requested)
}

export function clearEmailAliases(): void {
  generation += 1
  emailAliases.set(null)
}

export const serviceNames = { addy: 'addy.io', simpleLogin: 'SimpleLogin' } as const
