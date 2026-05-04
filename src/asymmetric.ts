/**
 * Asymmetric primitives — Ed25519 sign/verify and X25519+ChaCha20-
 * Poly1305 sealed-box style encryption. Same wire formats as the Go
 * counterpart.
 */

import {
  createPrivateKey,
  createPublicKey,
  createCipheriv,
  createDecipheriv,
  diffieHellman,
  generateKeyPairSync,
  randomBytes as nodeRandom,
  sign as nodeSign,
  verify as nodeVerify,
  type CipherGCM,
  type DecipherGCM,
  type KeyObject,
} from "node:crypto"
import { Buffer } from "node:buffer"

import { AEAD_NONCE_SIZE } from "./format.js"
import {
  CiphertextTooShortError,
  CryptError,
  InvalidCiphertextError,
  InvalidKeyError,
  TamperedError,
  UnsupportedVersionError,
} from "./errors.js"

export const ED25519_PUBLIC_KEY_SIZE = 32
export const ED25519_PRIVATE_KEY_SIZE = 32 // raw seed; we wrap into KeyObject internally
export const ED25519_SIGNATURE_SIZE = 64

export const X25519_KEY_SIZE = 32
const VERSION_ASYMMETRIC_V1 = 0x05
const TAG_SIZE = 16

export class InvalidSignatureError extends CryptError {
  override readonly name = "InvalidSignatureError"
}

// ----- Ed25519 -----

export interface Ed25519KeyPair {
  publicKey: Buffer // 32 bytes
  privateKey: Buffer // 32-byte seed
}

/**
 * Generate a fresh Ed25519 keypair.
 */
/**
 * Generate a fresh Ed25519 keypair from the OS CSPRNG.
 *
 * @example
 * ```ts
 * const { publicKey, privateKey } = generateEd25519()
 * const sig = signEd25519(privateKey, body)
 * verifyEd25519(publicKey, body, sig) // true
 * ```
 */
export function generateEd25519(): Ed25519KeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519")
  const pubRaw = publicKey.export({ format: "der", type: "spki" })
  const privRaw = privateKey.export({ format: "der", type: "pkcs8" })
  // The DER encoding wraps the raw key in a few bytes of metadata.
  // Public key: last 32 bytes are the raw key.
  // Private key: last 32 bytes are the raw seed.
  return {
    publicKey: pubRaw.subarray(pubRaw.length - 32),
    privateKey: privRaw.subarray(privRaw.length - 32),
  }
}

function ed25519PublicKeyObject(pub: Buffer): KeyObject {
  // Wrap raw 32-byte public key in DER for Node's KeyObject API.
  const der = Buffer.concat([
    Buffer.from([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]),
    pub,
  ])
  return createPublicKey({ key: der, format: "der", type: "spki" })
}

function ed25519PrivateKeyObject(priv: Buffer): KeyObject {
  const der = Buffer.concat([
    Buffer.from([
      0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
      0x20,
    ]),
    priv,
  ])
  return createPrivateKey({ key: der, format: "der", type: "pkcs8" })
}

/**
 * Sign data using Ed25519. Returns a 64-byte signature.
 */
export function signEd25519(privateKey: Buffer | Uint8Array, data: Buffer | Uint8Array): Buffer {
  const priv = Buffer.from(privateKey)
  if (priv.length !== ED25519_PRIVATE_KEY_SIZE) {
    throw new InvalidKeyError(
      `crypt: ed25519 private key must be ${ED25519_PRIVATE_KEY_SIZE} bytes; got ${priv.length}`,
    )
  }
  const keyObj = ed25519PrivateKeyObject(priv)
  return nodeSign(null, Buffer.from(data), keyObj)
}

/**
 * Verify an Ed25519 signature. Returns boolean (no throw) on
 * mismatch; throws InvalidKeyError or InvalidSignatureError on
 * shape errors.
 */
export function verifyEd25519(
  publicKey: Buffer | Uint8Array,
  data: Buffer | Uint8Array,
  signature: Buffer | Uint8Array,
): boolean {
  const pub = Buffer.from(publicKey)
  if (pub.length !== ED25519_PUBLIC_KEY_SIZE) {
    throw new InvalidKeyError(
      `crypt: ed25519 public key must be ${ED25519_PUBLIC_KEY_SIZE} bytes; got ${pub.length}`,
    )
  }
  const sig = Buffer.from(signature)
  if (sig.length !== ED25519_SIGNATURE_SIZE) {
    throw new InvalidSignatureError(
      `crypt: ed25519 signature must be ${ED25519_SIGNATURE_SIZE} bytes; got ${sig.length}`,
    )
  }
  return nodeVerify(null, Buffer.from(data), ed25519PublicKeyObject(pub), sig)
}

// ----- X25519 + ChaCha20-Poly1305 sealed-box -----

export interface X25519KeyPair {
  publicKey: Buffer
  privateKey: Buffer
}

export function generateKeyPair(): X25519KeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("x25519")
  const pubRaw = publicKey.export({ format: "der", type: "spki" })
  const privRaw = privateKey.export({ format: "der", type: "pkcs8" })
  return {
    publicKey: pubRaw.subarray(pubRaw.length - 32),
    privateKey: privRaw.subarray(privRaw.length - 32),
  }
}

function x25519PublicKeyObject(pub: Buffer): KeyObject {
  const der = Buffer.concat([
    Buffer.from([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00]),
    pub,
  ])
  return createPublicKey({ key: der, format: "der", type: "spki" })
}

function x25519PrivateKeyObject(priv: Buffer): KeyObject {
  const der = Buffer.concat([
    Buffer.from([
      0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04,
      0x20,
    ]),
    priv,
  ])
  return createPrivateKey({ key: der, format: "der", type: "pkcs8" })
}

/**
 * Encrypt plaintext to recipientPublicKey using X25519 + ChaCha20-
 * Poly1305 (sealed-box style). Anyone with the matching private key
 * can decrypt; nobody else can. Sender identity is NOT authenticated.
 *
 * To authenticate the sender, sign the plaintext with Ed25519 before
 * sealing.
 *
 * @example
 * ```ts
 * const { publicKey, privateKey } = generateKeyPair()
 * const ct = sealAsymmetric(publicKey, "secret message")
 * const pt = openAsymmetric(privateKey, ct).toString("utf8")
 * ```
 */
export function sealAsymmetric(
  recipientPublicKey: Buffer | Uint8Array,
  plaintext: Buffer | string | Uint8Array,
): string {
  const pub = Buffer.from(recipientPublicKey)
  if (pub.length !== X25519_KEY_SIZE) {
    throw new InvalidKeyError(
      `crypt: recipient public key must be ${X25519_KEY_SIZE} bytes; got ${pub.length}`,
    )
  }

  // Generate ephemeral keypair.
  const { publicKey: ephPub, privateKey: ephPriv } = generateKeyPair()

  // ECDH.
  const shared = diffieHellman({
    privateKey: x25519PrivateKeyObject(ephPriv),
    publicKey: x25519PublicKeyObject(pub),
  })

  // Encrypt under shared key with random nonce. AAD = ephPub.
  const nonce = nodeRandom(AEAD_NONCE_SIZE)
  const cipher = createCipheriv("chacha20-poly1305", shared, nonce, {
    authTagLength: TAG_SIZE,
  }) as CipherGCM
  cipher.setAAD(ephPub)
  const pt = typeof plaintext === "string" ? Buffer.from(plaintext, "utf8") : Buffer.from(plaintext)
  const ct1 = cipher.update(pt)
  const ct2 = cipher.final()
  const tag = cipher.getAuthTag()

  return Buffer.concat([
    Buffer.from([VERSION_ASYMMETRIC_V1]),
    ephPub,
    nonce,
    ct1,
    ct2,
    tag,
  ]).toString("base64url")
}

/**
 * Decrypt a sealAsymmetric output with the recipient's private key.
 */
export function openAsymmetric(
  recipientPrivateKey: Buffer | Uint8Array,
  ciphertext: string,
): Buffer {
  const priv = Buffer.from(recipientPrivateKey)
  if (priv.length !== X25519_KEY_SIZE) {
    throw new InvalidKeyError(
      `crypt: recipient private key must be ${X25519_KEY_SIZE} bytes; got ${priv.length}`,
    )
  }
  let raw: Buffer
  try {
    raw = Buffer.from(ciphertext, "base64url")
  } catch (e) {
    throw new InvalidCiphertextError(`crypt: base64url decode: ${(e as Error).message}`)
  }
  const minSize = 1 + X25519_KEY_SIZE + AEAD_NONCE_SIZE + TAG_SIZE
  if (raw.length < minSize) {
    throw new CiphertextTooShortError(`crypt: ciphertext must be >= ${minSize} bytes`)
  }
  if (raw[0] !== VERSION_ASYMMETRIC_V1) {
    throw new UnsupportedVersionError(
      `crypt: unsupported asymmetric ciphertext version 0x${raw[0]?.toString(16).padStart(2, "0")}`,
    )
  }
  const ephPub = raw.subarray(1, 1 + X25519_KEY_SIZE)
  const nonce = raw.subarray(1 + X25519_KEY_SIZE, 1 + X25519_KEY_SIZE + AEAD_NONCE_SIZE)
  const tag = raw.subarray(raw.length - TAG_SIZE)
  const body = raw.subarray(1 + X25519_KEY_SIZE + AEAD_NONCE_SIZE, raw.length - TAG_SIZE)

  const shared = diffieHellman({
    privateKey: x25519PrivateKeyObject(priv),
    publicKey: x25519PublicKeyObject(ephPub),
  })

  const decipher = createDecipheriv("chacha20-poly1305", shared, nonce, {
    authTagLength: TAG_SIZE,
  }) as DecipherGCM
  decipher.setAAD(ephPub)
  decipher.setAuthTag(tag)
  try {
    return Buffer.concat([decipher.update(body), decipher.final()])
  } catch (e) {
    throw new TamperedError(`crypt: ciphertext authentication failed: ${(e as Error).message}`)
  }
}
