/* @vitest-environment jsdom */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createFeedbackController } from './feedback-controller'

beforeEach(() => vi.useFakeTimers())
afterEach(() => vi.useRealTimers())

describe('notice timing', () => {
  it('hides a notice after a few seconds', () => {
    const feedback = createFeedbackController()
    feedback.showNotice('Copied', 'Fictional message')
    vi.advanceTimersByTime(4_799)
    expect(feedback.state.value().notice).not.toBeNull()
    vi.advanceTimersByTime(1)
    expect(feedback.state.value().notice).toBeNull()
  })

  it('keeps a notice while it is held', () => {
    const feedback = createFeedbackController()
    feedback.showNotice('Copied', 'Fictional message')
    vi.advanceTimersByTime(2_000)
    feedback.holdNotice()
    vi.advanceTimersByTime(60_000)
    expect(feedback.state.value().notice).not.toBeNull()
  })

  it('hides a held notice after the time that was left once it is released', () => {
    const feedback = createFeedbackController()
    feedback.showNotice('Copied', 'Fictional message')
    vi.advanceTimersByTime(2_000)
    feedback.holdNotice()
    vi.advanceTimersByTime(10_000)
    feedback.resumeNotice()
    vi.advanceTimersByTime(2_799)
    expect(feedback.state.value().notice).not.toBeNull()
    vi.advanceTimersByTime(1)
    expect(feedback.state.value().notice).toBeNull()
  })

  it('leaves at least a second to read after release', () => {
    const feedback = createFeedbackController()
    feedback.showNotice('Copied', 'Fictional message')
    vi.advanceTimersByTime(4_700)
    feedback.holdNotice()
    feedback.resumeNotice()
    vi.advanceTimersByTime(999)
    expect(feedback.state.value().notice).not.toBeNull()
    vi.advanceTimersByTime(1)
    expect(feedback.state.value().notice).toBeNull()
  })

  it('starts a new notice with the full time even after a hold', () => {
    const feedback = createFeedbackController()
    feedback.showNotice('Copied', 'First')
    feedback.holdNotice()
    feedback.showNotice('Saved', 'Second')
    vi.advanceTimersByTime(4_799)
    expect(feedback.state.value().notice?.title).toBe('Saved')
    vi.advanceTimersByTime(1)
    expect(feedback.state.value().notice).toBeNull()
  })

  it('ignores a release when no notice is showing', () => {
    const feedback = createFeedbackController()
    feedback.resumeNotice()
    vi.advanceTimersByTime(10_000)
    expect(feedback.state.value().notice).toBeNull()
  })
})
