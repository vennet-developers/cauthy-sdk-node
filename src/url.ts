/**
 * The address without its trailing slashes: `https://auth.example.com/` and
 * `https://auth.example.com` name the same issuer. A loop, not `/\/+$/`,
 * which backtracks over a long run of slashes.
 */
export function withoutTrailingSlashes(s: string): string {
  let end = s.length
  while (end > 0 && s.charCodeAt(end - 1) === 47) end--
  return s.slice(0, end)
}
