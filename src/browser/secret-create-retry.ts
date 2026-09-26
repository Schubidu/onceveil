import { encryptSecret, type EncryptedShare } from './secret-crypto'

export interface PendingEncryptedCreate {
  secret: string
  encrypted: EncryptedShare
}

export async function encryptedShareForCreate(
  secret: string,
  pending: PendingEncryptedCreate | undefined,
  encrypt: (plaintext: string) => Promise<EncryptedShare> = encryptSecret,
): Promise<PendingEncryptedCreate> {
  if (pending?.secret === secret) {
    return pending
  }

  return {
    secret,
    encrypted: await encrypt(secret),
  }
}
