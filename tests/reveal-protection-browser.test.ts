import { afterEach, describe, expect, it, vi } from 'vitest'

vi.mock('altcha', () => ({}))

import { startRevealProtection } from '../src/browser/reveal-protection'
import type { SecretId } from '../src/core/secret'

const SECRET_ID = '0123456789abcdef0123456789abcdef' as SecretId

class FakeElement extends EventTarget {
  readonly attributes = new Map<string, string>()
  removed = false

  setAttribute(name: string, value: string) {
    this.attributes.set(name, value)
  }

  remove() {
    this.removed = true
  }
}

class FakeScript {
  src = ''
  async = false
  defer = false
  removed = false
  onload?: () => void
  onerror?: () => void

  remove() {
    this.removed = true
  }
}

class FakeContainer {
  child?: FakeElement

  replaceChildren(child: FakeElement) {
    this.child = child
  }
}

function customEvent(type: string, detail: unknown): Event {
  const event = new Event(type)
  Object.defineProperty(event, 'detail', { value: detail })
  return event
}

describe('reveal protection browser providers', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('activates ALTCHA with the inline challenge and forwards the verified payload', async () => {
    const widget = new FakeElement()
    const container = new FakeContainer()
    const verified = vi.fn()
    const failed = vi.fn()
    const status = vi.fn()
    const challenge = {
      algorithm: 'PBKDF2/SHA-256',
      parameters: { cost: 5_000 },
      signature: 'signed-challenge',
    }

    vi.stubGlobal('document', {
      createElement(tagName: string) {
        expect(tagName).toBe('altcha-widget')
        return widget
      },
    })

    const cleanup = await startRevealProtection(
      { provider: 'altcha', challenge },
      container as unknown as HTMLElement,
      SECRET_ID,
      { verified, failed, status },
    )

    expect(container.child).toBe(widget)
    expect(widget.attributes.get('challenge')).toBe(JSON.stringify(challenge))
    expect(widget.attributes.get('auto')).toBe('onload')
    expect(widget.attributes.get('type')).toBe('checkbox')
    expect(status).toHaveBeenCalledWith('Computing proof-of-work verification…')

    widget.dispatchEvent(customEvent('verified', { payload: 'altcha-payload' }))

    expect(verified).toHaveBeenCalledWith('altcha-payload')
    expect(failed).not.toHaveBeenCalled()

    cleanup()
    expect(widget.removed).toBe(true)
  })

  it.each(['error', 'expired'])('fails closed when ALTCHA enters %s state', async (state) => {
    const widget = new FakeElement()
    const container = new FakeContainer()
    const verified = vi.fn()
    const failed = vi.fn()

    vi.stubGlobal('document', {
      createElement() {
        return widget
      },
    })

    await startRevealProtection(
      { provider: 'altcha', challenge: { signature: 'signed-challenge' } },
      container as unknown as HTMLElement,
      SECRET_ID,
      { verified, failed, status: vi.fn() },
    )

    widget.dispatchEvent(customEvent('statechange', { state }))

    expect(failed).toHaveBeenCalledWith('Verification failed. Close this window and try again.')
    expect(verified).not.toHaveBeenCalled()
  })

  it('ignores Turnstile loader and verification callbacks after cleanup', async () => {
    const script = new FakeScript()
    const render = vi.fn()
    const verified = vi.fn()
    const failed = vi.fn()
    const status = vi.fn()

    vi.stubGlobal('window', { turnstile: { render } })
    vi.stubGlobal('document', {
      createElement(tagName: string) {
        expect(tagName).toBe('script')
        return script
      },
      head: {
        append(candidate: FakeScript) {
          expect(candidate).toBe(script)
        },
      },
    })

    const cleanup = await startRevealProtection(
      { provider: 'turnstile', siteKey: 'site-key', action: 'onceveil_reveal' },
      {} as HTMLElement,
      SECRET_ID,
      { verified, failed, status },
    )

    cleanup()
    script.onload?.()

    expect(script.removed).toBe(true)
    expect(render).not.toHaveBeenCalled()
    expect(verified).not.toHaveBeenCalled()
    expect(failed).not.toHaveBeenCalled()
    expect(status).not.toHaveBeenCalled()
  })

  it('ignores Turnstile widget callbacks after cleanup', async () => {
    const script = new FakeScript()
    let renderedOptions:
      | {
          callback(token: string): void
          'error-callback'(): void
          'expired-callback'(): void
        }
      | undefined
    const verified = vi.fn()
    const failed = vi.fn()

    vi.stubGlobal('window', {
      turnstile: {
        render(
          _container: HTMLElement,
          options: {
            callback(token: string): void
            'error-callback'(): void
            'expired-callback'(): void
          },
        ) {
          renderedOptions = options
          return 'widget-id'
        },
      },
    })
    vi.stubGlobal('document', {
      createElement() {
        return script
      },
      head: { append() {} },
    })

    const cleanup = await startRevealProtection(
      { provider: 'turnstile', siteKey: 'site-key', action: 'onceveil_reveal' },
      {} as HTMLElement,
      SECRET_ID,
      { verified, failed, status: vi.fn() },
    )

    script.onload?.()
    cleanup()
    renderedOptions?.callback('late-token')
    renderedOptions?.['error-callback']()
    renderedOptions?.['expired-callback']()

    expect(verified).not.toHaveBeenCalled()
    expect(failed).not.toHaveBeenCalled()
  })

  it('rejects an ALTCHA verified event without a string payload', async () => {
    const widget = new FakeElement()
    const container = new FakeContainer()
    const verified = vi.fn()
    const failed = vi.fn()

    vi.stubGlobal('document', {
      createElement() {
        return widget
      },
    })

    await startRevealProtection(
      { provider: 'altcha', challenge: { signature: 'signed-challenge' } },
      container as unknown as HTMLElement,
      SECRET_ID,
      { verified, failed, status: vi.fn() },
    )

    widget.dispatchEvent(customEvent('verified', { payload: 42 }))

    expect(failed).toHaveBeenCalledWith('Verification failed. Close this window and try again.')
    expect(verified).not.toHaveBeenCalled()
  })
})
