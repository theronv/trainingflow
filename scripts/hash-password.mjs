/**
 * Generate an ADMIN_PASSWORD_HASH value for the TrainFlow Worker.
 *
 * Usage:
 *   node scripts/hash-password.mjs <your-password>
 *
 * Then set the printed hash as a Cloudflare Worker secret:
 *   wrangler secret put ADMIN_PASSWORD_HASH
 *
 * Requires Node.js 19+ (globalThis.crypto.subtle is stable from 19).
 * On Node 18 add the --experimental-global-webcrypto flag.
 */

const password = process.argv[2]

if (!password) {
  console.error('Usage: node scripts/hash-password.mjs <password>')
  process.exit(1)
}

if (password.length < 8) {
  console.error('Password must be at least 8 characters.')
  process.exit(1)
}

const ENC  = new TextEncoder()
const salt = globalThis.crypto.getRandomValues(new Uint8Array(16))

const key = await globalThis.crypto.subtle.importKey(
  'raw', ENC.encode(password), 'PBKDF2', false, ['deriveBits']
)

const bits = await globalThis.crypto.subtle.deriveBits(
  { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 100_000 },
  key, 256
)

function b64(bytes) { return btoa(String.fromCharCode(...bytes)) }

const hash = `pbkdf2v1:${b64(salt)}:${b64(new Uint8Array(bits))}`

console.log('\nADMIN_PASSWORD_HASH value (copy this):\n')
console.log(hash)
console.log('\nRun:  wrangler secret put ADMIN_PASSWORD_HASH')
console.log('Then paste the hash above when prompted.\n')
