import { createFileRoute } from '@tanstack/react-router'

import { isValidSecretId } from '../core/secret'
import {
  prepareRevealProofResponse,
  protectedRevealResponse,
  verifyRevealProofResponse,
} from '../runtime/reveal-protection-http'
import {
  getRevealChallengeVerifier,
  getRevealProofRepository,
  getTurnstileSiteKey,
  RevealProtectionUnavailableError,
} from '../runtime/reveal-protection'
import {
  assertSecretDatabaseEnvironment,
  getSecretRepository,
  SecretDatabaseEnvironmentError,
  SecretDatabaseUnavailableError,
} from '../runtime/secret-repository'
import { runtimeEnvironmentForRequest } from '../runtime/readiness'
import { withSecretSecurityHeaders } from '../runtime/security-headers'
import { REVEAL_PROTECTION_ACTION } from '../core/reveal-protection'
import { RevealProofStorageError } from '../adapters/d1-reveal-proof-repository'

function jsonError(error: string, status: number): Response {
  return withSecretSecurityHeaders(Response.json({ error }, { status }))
}

export const Route = createFileRoute('/api/secrets/$id/reveal')({
  server: {
    handlers: {
      GET: async ({ params, request }) => {
        if (request.headers.get('X-Onceveil-Proof-Config') !== '1' || !isValidSecretId(params.id)) {
          return jsonError('not_found', 404)
        }

        try {
          return withSecretSecurityHeaders(
            Response.json(
              {
                provider: 'turnstile',
                siteKey: getTurnstileSiteKey(),
                action: REVEAL_PROTECTION_ACTION,
              },
              { status: 200 },
            ),
          )
        } catch (error) {
          if (error instanceof RevealProtectionUnavailableError) {
            return jsonError('verification_unavailable', 503)
          }

          throw error
        }
      },
      POST: async ({ params, request }) => {
        const expectedEnvironment = runtimeEnvironmentForRequest(request)
        if (!expectedEnvironment) {
          return jsonError('service_unavailable', 503)
        }

        if (!isValidSecretId(params.id)) {
          return jsonError('not_found', 404)
        }

        try {
          await assertSecretDatabaseEnvironment(expectedEnvironment)

          if (request.headers.get('X-Onceveil-Proof-Prepare') === '1') {
            getTurnstileSiteKey()
            return await prepareRevealProofResponse(params.id, getRevealProofRepository())
          }

          if (request.headers.get('X-Onceveil-Proof-Request') === '1') {
            return await verifyRevealProofResponse(
              request,
              params.id,
              getRevealChallengeVerifier(),
              getRevealProofRepository(),
            )
          }

          if (request.headers.get('X-Onceveil-Reveal') !== '1') {
            return jsonError('reveal_intent_required', 400)
          }

          return await protectedRevealResponse(
            request,
            params.id,
            getRevealProofRepository(),
            getSecretRepository(),
          )
        } catch (error) {
          if (
            error instanceof SecretDatabaseUnavailableError ||
            error instanceof RevealProtectionUnavailableError ||
            error instanceof RevealProofStorageError
          ) {
            return jsonError('service_unavailable', 503)
          }

          if (error instanceof SecretDatabaseEnvironmentError) {
            console.error('secret database environment check failed', {
              expected: error.expected,
              actual: error.actual,
            })
            return jsonError('service_unavailable', 503)
          }

          console.error('protected secret reveal failed', {
            name: error instanceof Error ? error.name : 'UnknownError',
            message: error instanceof Error ? error.message : 'unknown error',
          })
          return jsonError('internal_error', 500)
        }
      },
    },
  },
})
