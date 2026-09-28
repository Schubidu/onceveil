import { D1McpHandoffRepository } from '../adapters/d1-mcp-handoff-repository'
import type { McpHandoffRepository } from '../core/mcp-handoff'
import type { OnceveilRequestContext } from './request-context'
import { getSecretDatabase } from './secret-repository'

export function getMcpHandoffRepository(context: OnceveilRequestContext): McpHandoffRepository {
  return new D1McpHandoffRepository(getSecretDatabase(context))
}
