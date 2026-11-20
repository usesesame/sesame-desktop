import { createServer } from 'node:http'

import { fixturePages as pages } from './browser-fixture-pages.mjs'

const host = '127.0.0.1'
const port = 17_891

const server = createServer((request, response) => {
  const body = pages[request.url] ?? 'Not found'
  response.writeHead(pages[request.url] ? 200 : 404, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' })
  response.end(body)
})

server.listen(port, host, () => {
  process.stdout.write(`Fictional browser fixtures are available at http://${host}:${port}/login, /multiple, and /password-change. Press Ctrl+C to stop.\n`)
})
