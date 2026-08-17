import { createServer } from 'node:http'

const host = '127.0.0.1'
const port = 17_891

const pages = {
  '/login': `<!doctype html><title>Sesame fictional login fixture</title>
    <form id="login-form"><label>Email <input id="username" type="email" autocomplete="username"></label>
    <label>Password <input id="password" type="password" autocomplete="current-password"></label>
    <button type="submit">Sign in</button></form>
    <output id="result"></output><script>document.querySelector('form').addEventListener('submit', event => { event.preventDefault(); document.querySelector('#result').textContent = 'not submitted' })</script>`,
  '/multiple': `<!doctype html><title>Sesame ambiguous fixture</title>
    <form><input type="password" autocomplete="current-password"></form>
    <form><input type="password" autocomplete="current-password"></form>`,
  '/password-change': `<!doctype html><title>Sesame password-change fixture</title>
    <form><input type="password" autocomplete="current-password"><input type="password" autocomplete="new-password"><input type="password" autocomplete="new-password"></form>`,
}

const server = createServer((request, response) => {
  const body = pages[request.url] ?? 'Not found'
  response.writeHead(pages[request.url] ? 200 : 404, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' })
  response.end(body)
})

server.listen(port, host, () => {
  process.stdout.write(`Fictional browser fixtures are available at http://${host}:${port}/login, /multiple, and /password-change. Press Ctrl+C to stop.\n`)
})
