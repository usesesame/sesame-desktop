import { writable } from 'svelte/store'
import { listNeverSaveSites, removeNeverSaveSite } from './vault'

export const neverSaveSites = writable<string[] | null>(null)

export async function loadNeverSaveSites(): Promise<void> {
  neverSaveSites.set(await listNeverSaveSites())
}

export async function forgetNeverSaveSite(origin: string): Promise<void> {
  neverSaveSites.set(await removeNeverSaveSite(origin))
}

export function clearNeverSaveSites(): void {
  neverSaveSites.set(null)
}
