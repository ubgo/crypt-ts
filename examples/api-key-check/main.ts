/**
 * Constant-time API key authentication using only the Node stdlib
 * http module — no framework. The server compares the incoming
 * X-API-Key header to the configured value in constant time.
 */

import { constantTimeEqual } from "@ubgo/crypt"
import { Buffer } from "node:buffer"
import http from "node:http"
import type { IncomingMessage, ServerResponse } from "node:http"

function requireAPIKey(
  expected: Buffer,
  next: (req: IncomingMessage, res: ServerResponse) => void,
): http.RequestListener {
  return (req, res) => {
    const provided = Buffer.from((req.headers["x-api-key"] as string) ?? "")
    if (!constantTimeEqual(provided, expected)) {
      res.statusCode = 401
      res.end("unauthorized\n")
      return
    }
    next(req, res)
  }
}

const expectedKey = Buffer.from("internal-api-key-from-config")

const server = http.createServer(
  requireAPIKey(expectedKey, (req, res) => {
    if (req.url === "/internal/health") {
      res.end("ok\n")
      return
    }
    res.statusCode = 404
    res.end("not found\n")
  }),
)

server.listen(0, async () => {
  const addr = server.address()
  if (!addr || typeof addr === "string") return
  const base = `http://localhost:${addr.port}`

  const correct = await fetch(`${base}/internal/health`, {
    headers: { "x-api-key": "internal-api-key-from-config" },
  })
  console.log(`with correct key:   ${correct.status} ${(await correct.text()).trim()}`)

  const wrong = await fetch(`${base}/internal/health`, {
    headers: { "x-api-key": "wrong" },
  })
  console.log(`with wrong key:     ${wrong.status} ${(await wrong.text()).trim()}`)

  const missing = await fetch(`${base}/internal/health`)
  console.log(`with missing key:   ${missing.status} ${(await missing.text()).trim()}`)

  server.close()
})
