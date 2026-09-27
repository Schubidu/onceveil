import { createFileRoute } from '@tanstack/react-router'

import { createRequestContext } from '#onceveil-runtime-context'

import { RevealProofStorageError } from '../adapters/d1-reveal-proof-repository'
import { REVEAL_PROTECTION_ACTION } from '../core/reveal-protection'
import { isValidSecretId } from '../core/secret'
import {
  prepareRevealProofResponse,
  protectedRevealResponse,
  verifyRevealProofResponse,
  verifyRevealProofWithoutChallengeResponse,
} from '../runtime/reveal-protection-http'
import {
  getRevealChallengeVerifier,
  getRevealProofRepository,
  getRevealProtectionProvider,
  getTurnstileSiteKey,
  RevealProtectionUnavailableError,
} from '../runtime/reveal-protection'
import {
  assertSecretDatabaseEnvironment,
  getSecretRepository,
  SecretDatabaseEnvironmentError,
  SecretDatabaseUnavailableError,
} from '../runtime/secret-repository'
import { logRuntimeError } from '../runtime/safe-log'
import { withSecretSecurityHeaders } from '../runtime/security-headers'

function jsonError(error: string, status: number): Response {
  return withSecretSecurityHeaders(Response.json({ error }, { status }))
}

export const Route = createFileRoute('/api/secrets/$id/reveal')({
  server: {
    handlers: {
      GET: async ({ params, request }) => {
        const runtime = createRequestContext(request)
        if (request.headers.get('X-Onceveil-Proof-Config') !== '1' || !isValidSecretId(params.id)) {
          return jsonError('not_found', 404)
        }

        try {
          const provider = getRevealProtectionProvider(runtime)
          if (provider === 'none') {
            return withSecretSecurityHeaders(Response.json({ provider }, { status: 200 }))
          }

          return withSecretSecurityHeaders(
            Response.json(
              {
                provider,
                siteKey: getTurnstileSiteKey(runtime),
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
        const runtime = createRequestContext(request)
        if (!isValidSecretId(params.id)) {
          return jsonError('not_found', 404)
        }

        try {
          await assertSecretDatabaseEnvironment(runtime)
          const provider = getRevealProtectionProvider(runtime)
          const proofs = getRevealProofRepository(runtime)

          if (request.headers.get('X-Onceveil-Proof-Prepare') === '1') {
            return await prepareRevealProofResponse(request, params.id, proofs)
          }

          if (request.headers.get('X-Onceveil-Proof-Request') === '1') {
            return provider === 'turnstile'
              ? await verifyRevealProofResponse(
                  request,
                  params.id,
                  getRevealChallengeVerifier(runtime),
                  proofs,
                )
              : await verifyRevealProofWithoutChallengeResponse(request, params.id, proofs)
          }

          if (request.headers.get('X-Onceveil-Reveal') !== '1') {
            return jsonError('reveal_intent_required', 400)
          }

          return await protectedRevealResponse(
            request,
            params.id,
            proofs,
            getSecretRepository(runtime),
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
            logRuntimeError('secret database environment check failed', error, {
              expected: error.expected,
              diagnostic: error.actual.startsWith('query-error:')
                ? 'query_error'
                : 'environment_mismatch',
            })
            return jsonError('service_unavailable', 503)
          }

          logRuntimeError('protected secret reveal failed', error)
          return jsonError('internal_error', 500)
        }
      },
    },
  },
})
