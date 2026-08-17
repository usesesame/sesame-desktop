import { timingSafeEqual } from 'node:crypto'
import { createReadStream, readFileSync, statSync } from 'node:fs'
import http from 'node:http'
import { isAbsolute, join, relative, resolve, sep } from 'node:path'

const args = process.argv.slice(2)
const valueFor = (name) => {
  const index = args.indexOf(name)
  return index >= 0 ? args[index + 1] : undefined
}
const rootArgument = valueFor('--root')
const mode = valueFor('--mode') ?? 'good'
if (!rootArgument || !['good', 'relabelled'].includes(mode)) {
  throw new Error('Usage: node tools/serve-updater-vm-lab.mjs --root <lab-directory> --mode <good|relabelled>')
}

const root = resolve(rootArgument)
const config = JSON.parse(readFileSync(join(root, 'lab-config.json'), 'utf8'))
if (config.host !== '127.0.0.1' || !Number.isInteger(config.port) || config.port < 1024 || config.port > 65535) {
  throw new Error('The updater VM lab must bind to an explicit high loopback port.')
}
const withinRoot = (file) => {
  const path = resolve(root, file)
  const location = relative(root, path)
  if (!location || location.startsWith(`..${sep}`) || location === '..' || isAbsolute(location)) {
    throw new Error(`Lab configuration path escapes its root: ${file}`)
  }
  return path
}
const capabilityEnvelope = readFileSync(withinRoot(config.capabilityEnvelope), 'utf8')
const manifest = readFileSync(
  withinRoot(mode === 'good' ? config.goodManifest : config.relabelledManifest),
  'utf8',
)
const artifact = withinRoot(config.updaterArtifact)
const artifactBytes = statSync(artifact).size
const expectedAuthorization = `Sesame ${config.accessToken}`
let linkRedeemed = false

function sameText(left, right) {
  const a = Buffer.from(left)
  const b = Buffer.from(right)
  return a.length === b.length && timingSafeEqual(a, b)
}

function json(response, status, value) {
  const body = Buffer.from(JSON.stringify(value))
  response.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': body.length,
    'Cache-Control': 'no-store',
  })
  response.end(body)
}

function authorized(request) {
  return sameText(request.headers.authorization ?? '', expectedAuthorization)
}

function readJSON(request) {
  return new Promise((resolveBody, reject) => {
    const chunks = []
    let bytes = 0
    request.on('data', (chunk) => {
      bytes += chunk.length
      if (bytes > 16 * 1024) {
        reject(new Error('request body too large'))
        request.destroy()
        return
      }
      chunks.push(chunk)
    })
    request.on('end', () => {
      try {
        resolveBody(JSON.parse(Buffer.concat(chunks).toString('utf8')))
      } catch (error) {
        reject(error)
      }
    })
    request.on('error', reject)
  })
}

const server = http.createServer(async (request, response) => {
  const url = new URL(request.url ?? '/', `http://${config.host}:${config.port}`)
  try {
    if (request.method === 'GET' && url.pathname === '/health') {
      json(response, 200, { ready: true, mode })
      return
    }
    if (request.method === 'GET' && url.pathname === '/v1/capabilities') {
      response.writeHead(200, {
        'Content-Type': 'application/json; charset=utf-8',
        'Content-Length': Buffer.byteLength(capabilityEnvelope),
        'Cache-Control': 'no-store',
      })
      response.end(capabilityEnvelope)
      return
    }
    if (request.method === 'GET' && url.pathname === '/latest.json') {
      response.writeHead(200, {
        'Content-Type': 'application/json; charset=utf-8',
        'Content-Length': Buffer.byteLength(manifest),
        'Cache-Control': 'no-store',
      })
      response.end(manifest)
      return
    }
    if (request.method === 'GET' && url.pathname === '/artifact') {
      response.writeHead(200, {
        'Content-Type': 'application/octet-stream',
        'Content-Length': artifactBytes,
        'Cache-Control': 'no-store',
      })
      createReadStream(artifact).pipe(response)
      return
    }
    if (request.method === 'POST' && url.pathname === '/v1/desktop/link') {
      const body = await readJSON(request)
      if (linkRedeemed || !sameText(body.code ?? '', config.linkCode)) {
        json(response, 401, { error: 'invalid_link_code' })
        return
      }
      linkRedeemed = true
      json(response, 201, {
        accessToken: config.accessToken,
        device: { deviceId: 'rel003-updater-lab-device', deviceName: 'Windows desktop' },
        expiresAt: '2030-01-01T00:00:00Z',
        syncAvailable: false,
      })
      return
    }
    if (!authorized(request)) {
      json(response, 401, { error: 'not_authenticated' })
      return
    }
    if (request.method === 'POST' && url.pathname === '/shutdown') {
      response.writeHead(204, { 'Cache-Control': 'no-store' })
      response.end(() => server.close())
      return
    }
    if (request.method === 'GET' && url.pathname === '/v1/desktop/status') {
      json(response, 200, {
        state: 'connected',
        connected: true,
        online: true,
        deviceName: 'Windows desktop',
        syncAvailable: false,
        browserHelperAvailable: false,
      })
      return
    }
    if (request.method === 'POST' && url.pathname === '/v1/desktop/heartbeat') {
      response.writeHead(204, { 'Cache-Control': 'no-store' })
      response.end()
      return
    }
    json(response, 404, { error: 'not_found' })
  } catch {
    if (!response.headersSent) json(response, 400, { error: 'invalid_request' })
    else response.destroy()
  }
})

server.listen(config.port, config.host, () => {
  console.log(`REL-003 updater lab listening on http://${config.host}:${config.port} in ${mode} mode.`)
})
