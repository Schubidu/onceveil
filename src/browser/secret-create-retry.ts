import {
  generateOwnerCapability,
  hashOwnerCapability,
  type OwnerCapability,
  type OwnerCapabilityHash,
} from '../core/owner-capability'
import { encryptSecret, type EncryptedShare } from './secret-crypto'

export interface PendingEncryptedCreate {
  secret: string
  encrypted: EncryptedShare
  ownerCapability: OwnerCapability
  ownerCapabilityHash: OwnerCapabilityHash
}

export async function encryptedShareForCreate(
  secret: string,
  pending: PendingEncryptedCreate | undefined,
  encrypt: (plaintext: string) => Promise<EncryptedShare> = encryptSecret,
): Promise<PendingEncryptedCreate> {
  if (pending?.secret === secret) {
    return pending
  }

  const ownerCapability = generateOwnerCapability()

  return {
    secret,
    encrypted: await encrypt(secret),
    ownerCapability,
    ownerCapabilityHash: await hashOwnerCapability(ownerCapability),
  }
}
