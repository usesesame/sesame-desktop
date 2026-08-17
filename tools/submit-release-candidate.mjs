import { readFile } from 'node:fs/promises'

const [candidatePath] = process.argv.slice(2)
const apiURL = process.env.SESAME_RELEASE_API_URL?.replace(/\/$/, '')
const token = process.env.SESAME_RELEASE_CANDIDATE_TOKEN?.trim()

if (!candidatePath || !apiURL || !/^https:\/\//.test(apiURL) || !token || !/^[A-Za-z0-9_-]{43}$/.test(token)) {
  throw new Error('Set SESAME_RELEASE_API_URL, SESAME_RELEASE_CANDIDATE_TOKEN, and pass a candidate JSON file.')
}

const candidate = JSON.parse(await readFile(candidatePath, 'utf8'))
const response = await fetch(`${apiURL}/v1/release-candidates`, {
  method: 'POST',
  headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
  body: JSON.stringify(candidate),
})
const body = await response.text()
if (response.status !== 201) throw new Error(`Release candidate submission failed (${response.status}): ${body.slice(0, 500)}`)
console.log(`Release candidate accepted: ${body}`)
