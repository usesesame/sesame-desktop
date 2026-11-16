import { writable } from 'svelte/store'
import { listNeverSaveSites, removeNeverSaveSite } from './vault'

export const neverSaveSites = writable<string[] | null>(null)

let generation = 0

export function neverSaveSitesGeneration(): number {
  return generation
}

export function publishNeverSaveSites(sites: string[], requested: number): boolean {
  if (requested !== generation) return false
  neverSaveSites.set(sites)
  return true
}

export async function loadNeverSaveSites(): Promise<void> {
  const requested = generation
  publishNeverSaveSites(await listNeverSaveSites(), requested)
}

export async function forgetNeverSaveSite(origin: string): Promise<void> {
  const requested = generation
  publishNeverSaveSites(await removeNeverSaveSite(origin), requested)
}

export function clearNeverSaveSites(): void {
  generation += 1
  neverSaveSites.set(null)
}
