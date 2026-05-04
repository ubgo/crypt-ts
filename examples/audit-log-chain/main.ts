/**
 * Audit log with HMAC-chained integrity.
 *
 * Each entry is signed with HMAC over (previous-MAC || payload).
 * Removing or modifying any entry breaks the chain.
 */

import { sign, verify } from "@ubgo/crypt"
import { Buffer } from "node:buffer"

interface AuditEntry {
  timestamp: Date
  actor: string
  action: string
  resource: string
  mac: Buffer
}

function payload(e: AuditEntry): Buffer {
  return Buffer.from(`${e.timestamp.toISOString()}|${e.actor}|${e.action}|${e.resource}`)
}

class AuditLog {
  readonly entries: AuditEntry[] = []
  constructor(private readonly secret: Buffer) {}

  append(actor: string, action: string, resource: string): void {
    const prev =
      this.entries.length === 0 ? Buffer.alloc(0) : this.entries[this.entries.length - 1]!.mac
    const entry: AuditEntry = {
      timestamp: new Date(),
      actor,
      action,
      resource,
      mac: Buffer.alloc(0),
    }
    const signed = Buffer.concat([prev, payload(entry)])
    entry.mac = sign(this.secret, signed)
    this.entries.push(entry)
  }

  /** Returns -1 if valid, otherwise the index of the first broken entry. */
  verify(): number {
    let prev = Buffer.alloc(0)
    for (let i = 0; i < this.entries.length; i++) {
      const e = this.entries[i]!
      const signed = Buffer.concat([prev, payload(e)])
      if (!verify(this.secret, signed, e.mac)) return i
      prev = e.mac
    }
    return -1
  }
}

const secret = Buffer.from("audit-log-secret-32-bytes-please")
const log = new AuditLog(secret)

log.append("usr_42", "login", "/auth")
log.append("usr_42", "view", "/billing")
log.append("usr_admin", "delete", "/users/usr_99")

if (log.verify() !== -1) {
  throw new Error(`chain broken at entry ${log.verify()}`)
}
console.log(`chain valid (${log.entries.length} entries)`)

for (let i = 0; i < log.entries.length; i++) {
  const e = log.entries[i]!
  console.log(
    `  [${i}] ${e.timestamp.toISOString()} ${e.actor} ${e.action} ${e.resource}  mac=${e.mac.subarray(0, 8).toString("hex")}`,
  )
}

console.log("\n--- attacker rewrites entry 1 ---")
log.entries[1]!.action = "purchase"
const broken = log.verify()
if (broken !== -1) {
  console.log(`chain broken at entry ${broken} (as expected)`)
}
