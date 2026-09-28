import { createFileRoute } from '@tanstack/react-router'

import { createRequestContext } from '#onceveil-runtime-context'

import { RevealProofStorageError } from '../adapters/d1-reveal-proof-repository'
import { isValidSecretId } from '../core/secret'
import {
  prepareRevealProofResponse,
  protectedRevealResponse,
  verifyRevealProofResponse,
} from '../runtime/reveal-protection-http'
import {
  getRevealProofRepository,
  getRevealProtectionClientConfig,
  getRevealProtectionProvider,
  getRevealProtectionVerifier,
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

const VERIFICATION_ID_PATTERN = /^[0-9a-f]{32}$/

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

        const verificationId = new URL(request.url).searchParams.get('verification')
        if (!verificationId || !VERIFICATION_ID_PATTERN.test(verificationId)) {
          return jsonError('invalid_verification', 400)
        }

        try {
          await assertSecretDatabaseEnvironment(runtime)
          const proofs = getRevealProofRepository(runtime)
          if (!(await proofs.hasPendingVerification(params.id, verificationId, Date.now()))) {
            return jsonError('verification_failed', 403)
          }

          const config = await getRevealProtectionClientConfig(runtime, params.id, verificationId)
          return withSecretSecurityHeaders(Response.json(config, { status: 200 }))
        } catch (error) {
          if (
            error instanceof SecretDatabaseUnavailableError ||
            error instanceof RevealProtectionUnavailableError ||
            error instanceof RevealProofStorageError
          ) {
            return jsonError('verification_unavailable', 503)
          }

          if (error instanceof SecretDatabaseEnvironmentError) {
            logRuntimeError('secret database environment check failed', error, {
              expected: error.expected,
              diagnostic: error.actual.startsWith('query-error:')
                ? 'query_error'
                : 'environment_mismatch',
            })
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
          getRevealProtectionProvider(runtime)
          const proofs = getRevealProofRepository(runtime)

          if (request.headers.get('X-Onceveil-Proof-Prepare') === '1') {
            return await prepareRevealProofResponse(request, params.id, proofs)
          }

          if (request.headers.get('X-Onceveil-Proof-Request') === '1') {
            return await verifyRevealProofResponse(
              request,
              params.id,
              getRevealProtectionVerifier(runtime),
              proofs,
            )
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
