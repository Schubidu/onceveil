import {
  createMcpHandler,
  createRequestStateCodec,
  inputRequired,
  McpServer,
  type CallToolResult,
  type InputRequiredResult,
} from '@modelcontextprotocol/server'
import * as z from 'zod/v4'

import { isValidMcpFlowId, type McpHandoffAction, type McpHandoffRecord } from '../core/mcp-handoff'
import { deriveMcpRequestStateKey } from './mcp-crypto'
import {
  cancelMcpHandoff,
  createMcpHandoff,
  getMcpHandoff,
  getMcpManagedSecretStatus,
  mcpHandoffUrl,
  revokeMcpManagedSecret,
} from './mcp-service'
import type { OnceveilRequestContext } from './request-context'

interface HandoffRequestState {
  action: McpHandoffAction
  flowId: string
}

type RequestStateCodec = ReturnType<typeof createRequestStateCodec<HandoffRequestState>>

const FLOW_SCHEMA = z.object({
  flowId: z.string().regex(/^[0-9a-f]{32}$/),
})

function textResult(text: string, structuredContent?: Record<string, unknown>): CallToolResult {
  return {
    content: [{ type: 'text', text }],
    ...(structuredContent ? { structuredContent } : {}),
  }
}

function toolError(message: string): CallToolResult {
  return {
    isError: true,
    content: [{ type: 'text', text: message }],
  }
}

function elicitationAction(ctx: {
  mcpReq: { inputResponses?: Record<string, unknown> }
}): string | undefined {
  const response = ctx.mcpReq.inputResponses?.browser
  if (typeof response !== 'object' || response === null || !('action' in response)) {
    return undefined
  }

  return typeof response.action === 'string' ? response.action : undefined
}

async function handoffTool(
  action: McpHandoffAction,
  context: OnceveilRequestContext,
  stateCodec: RequestStateCodec,
  ctx: Parameters<Parameters<McpServer['registerTool']>[2]>[1],
): Promise<CallToolResult | InputRequiredResult> {
  try {
    const state = ctx.mcpReq.requestState<HandoffRequestState>()
    let record: McpHandoffRecord | undefined

    if (state) {
      if (state.action !== action || !isValidMcpFlowId(state.flowId)) {
        return toolError('The browser handoff state is invalid.')
      }
      record = await getMcpHandoff(context, state.flowId)
    } else {
      record = await createMcpHandoff(context, action)
    }

    if (!record || record.action !== action) {
      return toolError('The browser handoff is no longer available.')
    }

    if (record.state === 'COMPLETED') {
      if (action === 'create') {
        const status = await getMcpManagedSecretStatus(context, record)
        if (!status) {
          return toolError('The managed secret is unavailable.')
        }

        return textResult('Secret creation handoff completed.', {
          flowId: record.flowId,
          state: status.state,
          expiresAtMs: status.expiresAtMs,
        })
      }

      return textResult('Reveal handoff completed. No secret data was returned to MCP.', {
        flowId: record.flowId,
        handoff: 'completed',
      })
    }

    if (Date.now() >= record.handoffExpiresAtMs) {
      return toolError('The browser handoff expired. Start the tool again.')
    }

    const responseAction = elicitationAction(ctx)
    if (responseAction === 'decline' || responseAction === 'cancel') {
      if (!(await cancelMcpHandoff(context, record.flowId))) {
        return toolError('The browser handoff could not be cancelled because it already changed state.')
      }

      return textResult('The browser handoff was cancelled.', {
        flowId: record.flowId,
        handoff: 'cancelled',
      })
    }

    const url = await mcpHandoffUrl(context, record)
    return inputRequired({
      inputRequests: {
        browser: inputRequired.elicitUrl({
          message:
            action === 'create'
              ? 'Open Onceveil to enter and encrypt the secret in your browser.'
              : 'Open Onceveil to paste the share link and reveal the secret in your browser.',
          url,
        }),
      },
      requestState: await stateCodec.mint({
        action,
        flowId: record.flowId,
      }),
    })
  } catch {
    return toolError('The MCP browser handoff could not be completed.')
  }
}

export async function buildOnceveilMcpServer(context: OnceveilRequestContext): Promise<McpServer> {
  if (context.mcp.status !== 'enabled') {
    throw new Error('mcp_unavailable')
  }

  const stateCodec = createRequestStateCodec<HandoffRequestState>({
    key: await deriveMcpRequestStateKey(context.mcp.storageKey),
    ttlSeconds: 10 * 60,
  })
  const server = new McpServer(
    { name: 'onceveil', version: '0.1.0' },
    {
      capabilities: { tools: {} },
      requestState: { verify: stateCodec.verify },
    },
  )

  server.registerTool(
    'create_secret_handoff',
    {
      title: 'Create one-time secret',
      description:
        'Open a secure browser handoff where the user enters and encrypts a secret. URL elicitation carries only a short-lived browser-transition capability; secret text and share capabilities are never returned to MCP.',
      inputSchema: z.object({}),
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: false,
      },
    },
    async (_input, ctx) => handoffTool('create', context, stateCodec, ctx),
  )

  server.registerTool(
    'reveal_secret_handoff',
    {
      title: 'Reveal one-time secret',
      description:
        'Open a secure browser handoff where the user pastes a Onceveil share link and completes the protected reveal. URL elicitation carries only a short-lived browser-transition capability; plaintext, ciphertext, and the share link are never returned to MCP.',
      inputSchema: z.object({}),
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: false,
        openWorldHint: false,
      },
    },
    async (_input, ctx) => handoffTool('reveal', context, stateCodec, ctx),
  )

  server.registerTool(
    'secret_status',
    {
      title: 'Secret status',
      description:
        'Read lifecycle status for a secret previously created through this authenticated MCP deployment. The flow ID is correlation-only.',
      inputSchema: FLOW_SCHEMA,
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    async ({ flowId }) => {
      try {
        if (!isValidMcpFlowId(flowId)) {
          return toolError('Managed secret not found.')
        }
        const record = await getMcpHandoff(context, flowId)
        if (!record) {
          return toolError('Managed secret not found.')
        }
        const status = await getMcpManagedSecretStatus(context, record)
        return status
          ? textResult(`Secret state: ${status.state}.`, {
              flowId,
              state: status.state,
              expiresAtMs: status.expiresAtMs,
            })
          : toolError('Managed secret not found.')
      } catch {
        return toolError('Secret status is unavailable.')
      }
    },
  )

  server.registerTool(
    'revoke_secret',
    {
      title: 'Revoke secret',
      description:
        'Revoke a secret previously created through this authenticated MCP deployment. This never grants recipient reveal access.',
      inputSchema: FLOW_SCHEMA,
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    async ({ flowId }) => {
      try {
        if (!isValidMcpFlowId(flowId)) {
          return toolError('Managed secret not found.')
        }
        const record = await getMcpHandoff(context, flowId)
        if (!record) {
          return toolError('Managed secret not found.')
        }
        const status = await revokeMcpManagedSecret(context, record)
        return status
          ? textResult(`Secret state: ${status.state}.`, {
              flowId,
              state: status.state,
              expiresAtMs: status.expiresAtMs,
            })
          : toolError('Managed secret not found.')
      } catch {
        return toolError('Secret revocation is unavailable.')
      }
    },
  )

  return server
}

export async function createOnceveilMcpHandler(context: OnceveilRequestContext) {
  return createMcpHandler(() => buildOnceveilMcpServer(context), {
    legacy: 'reject',
  })
}
