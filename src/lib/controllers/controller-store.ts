import { get, writable } from 'svelte/store'

export function controllerStore<T>(initial: T) {
  const store = writable(initial)
  return {
    subscribe: store.subscribe,
    set: store.set,
    patch(values: Partial<T>) {
      store.update((state) => ({ ...state, ...values }))
    },
    update(mutator: (state: T) => T) {
      store.update(mutator)
    },
    value() {
      return get(store)
    },
  }
}
