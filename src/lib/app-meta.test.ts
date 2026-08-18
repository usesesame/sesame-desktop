import { describe, expect, it } from 'vitest'
import { channelForVersion } from './app-meta'

describe('channelForVersion', () => {
  it('calls a pre-1.0 release a beta', () => {
    expect(channelForVersion('0.1.0')).toBe('Beta')
    expect(channelForVersion('0.14.2')).toBe('Beta')
  })

  it('stops calling it a beta once it reaches 1.0', () => {
    expect(channelForVersion('1.0.0')).toBe('Stable')
    expect(channelForVersion('2.3.1')).toBe('Stable')
  })

  it('reports the pre-release label ahead of the version number', () => {
    expect(channelForVersion('1.0.0-rc.1')).toBe('Rc')
    expect(channelForVersion('0.2.0-alpha.3')).toBe('Alpha')
  })

  it('says nothing rather than guessing when the version is not usable yet', () => {
    expect(channelForVersion('')).toBe('')
    expect(channelForVersion('unreleased')).toBe('')
  })
})
