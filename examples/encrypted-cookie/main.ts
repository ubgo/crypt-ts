/**
 * Encrypted session cookie. Entire session payload lives in the
 * cookie value, sealed with the server's key. No DB / Redis lookups
 * per request.
 *
 * Uses Node's stdlib http module — no framework. The same shape
 * applies to Express, Fastify, Hono, etc.
 */

import { Sealer } from "@ubgo/crypt"
import { Buffer } from "node:buffer"
import http from "node:http"
import type { IncomingMessage, ServerResponse } from "node:http"

const COOKIE_NAME = "_session"
const COOKIE_AAD = "cookie-v1"
const TTL_S = 60 * 60

interface SessionCookie {
  u: string
  e: number
}

function setSession(res: ServerResponse, sealer: Sealer, userID: string): void {
  const expiresAt = Math.floor(Date.now() / 1000) + TTL_S
  const value = sealer.seal(
    JSON.stringify({ u: userID, e: expiresAt } satisfies SessionCookie),
    Buffer.from(COOKIE_AAD),
  )
  const expires = new Date(expiresAt * 1000).toUTCString()
  res.setHeader(
    "Set-Cookie",
    `${COOKIE_NAME}=${value}; HttpOnly; Path=/; Expires=${expires}; SameSite=Lax`,
  )
}

function getSession(req: IncomingMessage, sealer: Sealer): SessionCookie {
  const cookieHeader = req.headers.cookie ?? ""
  const match = cookieHeader.split(/;\s*/).find((c) => c.startsWith(`${COOKIE_NAME}=`))
  if (!match) throw new Error("no session")
  const value = match.slice(COOKIE_NAME.length + 1)
  let pt: Buffer
  try {
    pt = sealer.open(value, Buffer.from(COOKIE_AAD))
  } catch {
    throw new Error("invalid session")
  }
  const s = JSON.parse(pt.toString("utf8")) as SessionCookie
  if (Math.floor(Date.now() / 1000) >= s.e) throw new Error("session expired")
  return s
}

const sealer = new Sealer(Buffer.from("01234567890123456789012345678901"))

const server = http.createServer((req, res) => {
  if (req.url === "/login") {
    setSession(res, sealer, "usr_42")
    res.end("logged in\n")
    return
  }
  if (req.url === "/me") {
    try {
      const s = getSession(req, sealer)
      res.end(`you are ${s.u}\n`)
    } catch (e) {
      res.statusCode = 401
      res.end(`${(e as Error).message}\n`)
    }
    return
  }
  res.statusCode = 404
  res.end("not found\n")
})

server.listen(0, async () => {
  const addr = server.address()
  if (!addr || typeof addr === "string") return
  const base = `http://localhost:${addr.port}`

  // 1. /login — capture cookie.
  const loginResp = await fetch(`${base}/login`)
  const setCookie = loginResp.headers.get("set-cookie") ?? ""
  console.log(`GET /login → ${loginResp.status}`)

  // 2. /me with cookie.
  const cookie = setCookie.split(";")[0] ?? ""
  const meResp = await fetch(`${base}/me`, { headers: { cookie } })
  console.log(`GET /me        → ${meResp.status} ${(await meResp.text()).trim()}`)

  // 3. /me without cookie.
  const meAnon = await fetch(`${base}/me`)
  console.log(`GET /me (none) → ${meAnon.status} ${(await meAnon.text()).trim()}`)

  server.close()
})
