export const NARROW_LAYOUT_QUERY = '(max-width: 960px)'

export function paneGridTemplate(listWidth: number, wide: boolean): string | undefined {
  return wide ? `grid-template-columns: ${listWidth}px auto minmax(0, 1fr)` : undefined
}
