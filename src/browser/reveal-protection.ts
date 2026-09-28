import { REVEAL_PROTECTION_ACTION } from '../core/reveal-protection'
import type { SecretId } from '../core/secret'

const TURNSTILE_SCRIPT_URL = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit'

interface TurnstileApi {
  render(
    container: HTMLElement,
    options: {
      sitekey: string
      action: string
      cData: string
      callback(token: string): void
      'error-callback'(): void
      'expired-callback'(): void
    },
  ): string
}

declare global {
  interface Window {
    turnstile?: TurnstileApi
  }
}

export interface RevealProtectionCallbacks {
  verified(token?: string): void | Promise<void>
  failed(message: string): void
  status(message: string): void
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null
}

export async function startRevealProtection(
  config: unknown,
  container: HTMLElement,
  secretId: SecretId,
  callbacks: RevealProtectionCallbacks,
): Promise<() => void> {
  let active = true

  if (!isRecord(config) || typeof config.provider !== 'string') {
    throw new Error('Reveal protection is unavailable')
  }

  if (config.provider === 'noop') {
    callbacks.status('No interactive verification is required. Returning to the secret…')
    await callbacks.verified()
    return () => undefined
  }

  if (config.provider === 'altcha') {
    if (!isRecord(config.challenge)) {
      throw new Error('Reveal protection is unavailable')
    }

    await import('altcha')

    const widget = document.createElement('altcha-widget')
    const verified = (event: Event) => {
      if (!active) {
        return
      }

      const payload = (event as CustomEvent<{ payload?: unknown }>).detail?.payload
      if (typeof payload !== 'string') {
        callbacks.failed('Verification failed. Close this window and try again.')
        return
      }

      void callbacks.verified(payload)
    }
    const stateChanged = (event: Event) => {
      if (!active) {
        return
      }

      const state = (event as CustomEvent<{ state?: unknown }>).detail?.state
      if (state === 'error' || state === 'expired') {
        callbacks.failed('Verification failed. Close this window and try again.')
      }
    }

    widget.setAttribute('challenge', JSON.stringify(config.challenge))
    widget.setAttribute('auto', 'onload')
    widget.setAttribute('type', 'checkbox')
    widget.addEventListener('verified', verified)
    widget.addEventListener('statechange', stateChanged)
    container.replaceChildren(widget)
    callbacks.status('Computing proof-of-work verification…')

    return () => {
      active = false
      widget.remove()
    }
  }

  if (
    config.provider !== 'turnstile' ||
    typeof config.siteKey !== 'string' ||
    config.action !== REVEAL_PROTECTION_ACTION
  ) {
    throw new Error('Reveal protection is unavailable')
  }

  const script = document.createElement('script')
  script.src = TURNSTILE_SCRIPT_URL
  script.async = true
  script.defer = true
  script.onload = () => {
    if (!active) {
      return
    }

    if (!window.turnstile) {
      callbacks.failed('Verification failed to initialize.')
      return
    }

    callbacks.status('Complete the verification to continue.')
    window.turnstile.render(container, {
      sitekey: config.siteKey as string,
      action: REVEAL_PROTECTION_ACTION,
      cData: secretId,
      callback: (token) => {
        if (active) {
          void callbacks.verified(token)
        }
      },
      'error-callback': () => {
        if (active) {
          callbacks.failed('Verification failed. Try again.')
        }
      },
      'expired-callback': () => {
        if (active) {
          callbacks.failed('Verification expired. Try again.')
        }
      },
    })
  }
  script.onerror = () => {
    if (active) {
      callbacks.failed('Verification failed to load.')
    }
  }
  document.head.append(script)

  return () => {
    active = false
    script.remove()
  }
}
