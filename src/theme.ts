// An application's look, for Cauthy's hosted pages.
//
// Cauthy's pages — sign-in, sign-up, the account page — can take the colours,
// corners, typeface and logo of the application that sends its people there,
// so signing in reads as a page of the application. A theme is a short list of
// values, which Cauthy checks one by one; it is never CSS.
//
// An application built with Stackmyth already has those values, as its
// `--sm-*` tokens. `themeFromStackmyth` reads them out of its stylesheets.

import { withoutTrailingSlashes } from './url'

/** How an application looks on Cauthy's hosted pages. Every value is optional. */
/** One font file the application serves: a family in one weight (or a range) and one style. */
export interface ThemeFont {
  family: string
  /** An https address of a `.woff2` file. It must answer with `Access-Control-Allow-Origin` for Cauthy's origin. */
  url: string
  /** `400`, or `"100 900"` for a variable font. Default: 400. */
  weight?: number | string
  style?: 'normal' | 'italic'
}

/** What an application says on its sign-in page, in one language. */
export interface ThemeTexts {
  /** Replaces "Sign in". */
  heading?: string
  /** Replaces "to continue to …". */
  subheading?: string
  /** The messages of the split layout's panel, shown one at a time (up to 5). */
  panel?: string[]
  /** Links at the foot of the split layout: privacy, terms (up to 4). */
  links?: { label: string; url: string }[]
}

export interface CauthyTheme {
  /** The page. Colours are `#rrggbb` or `rgba(r, g, b, a)`. */
  background?: string
  /** The card, and inputs. */
  surface?: string
  /** Headings and what is typed. */
  text?: string
  /** Paragraphs, labels, small print. */
  textMuted?: string
  border?: string
  /** The fields and the secondary buttons, when they are not the card's colours. */
  inputBackground?: string
  inputBorder?: string
  /** The main button, and what is written on it. */
  primary?: string
  primaryText?: string
  /** Links, and the focus ring. */
  accent?: string
  error?: string
  errorBackground?: string
  success?: string
  successBackground?: string
  /** Corners of cards and inputs, in pixels (0–40). */
  radius?: number
  /** Corners of buttons, in pixels (0–40). */
  buttonRadius?: number
  /** A CSS font-family list: the application's typeface first, a system font after it. */
  fontFamily?: string
  /** The files of the typefaces `fontFamily` names, for people who do not have them installed. */
  fonts?: ThemeFont[]
  /** An image shown where "Cauthy" is, over https. */
  logoUrl?: string
  /**
   * How the sign-in pages are laid out: `card` (the default, one card in the
   * middle) or `split` (the form on one side, a panel that presents the
   * application on the other).
   */
  layout?: 'card' | 'split'
  /** The colours the split layout's backdrop blends, one to four. */
  panelColors?: string[]
  /** The colour of what is written on the panel. */
  panelText?: string
  /** An https image shown over the panel's messages. */
  panelIconUrl?: string
  /** The application's own words on the sign-in page, by language (`en`, `es`). */
  texts?: Record<string, ThemeTexts>
  /**
   * The application's Stackmyth tokens (`--sm-*`), from `tokensFromStackmyth`.
   * Cauthy's pages are drawn with Stackmyth's components, so these make its
   * buttons and fields the application's own. They are laid over the named values.
   */
  tokens?: Record<string, string>
}

export interface StackmythThemeOptions {
  /**
   * The named theme to read, when the stylesheet keeps several under
   * `[data-theme=…]` (`"vennet"`). Without it only what applies to every
   * page (`:root`) is read.
   */
  theme?: string
  /** Which of the application's two modes to take. Default: `light`. */
  mode?: 'light' | 'dark'
  logoUrl?: string
}

export interface ImportedTheme {
  theme: CauthyTheme
  /** Tokens that were there and could not be carried over, and why. */
  warnings: string[]
}

const MAX_RADIUS = 40

// ── Reading custom properties out of CSS ───────────────────────────────────

interface Declaration {
  name: string
  value: string
  /** The selectors and at-rules it sits inside, outermost first. */
  within: string[]
}

// The stylesheet without its /* comments */, read in one pass. An unclosed
// comment runs to the end, as a browser reads it.
function withoutComments(css: string): string {
  let out = ''
  let i = 0
  for (;;) {
    const open = css.indexOf('/*', i)
    if (open < 0) return out + css.slice(i)
    out += css.slice(i, open)
    const close = css.indexOf('*/', open + 2)
    if (close < 0) return out
    i = close + 2
  }
}

function declarations(css: string): Declaration[] {
  const text = withoutComments(css)
  const out: Declaration[] = []
  const within: string[] = []
  let chunk = ''
  let quote = ''
  let depth = 0 // parentheses, so a `;` inside url(…) does not end anything
  const flush = () => {
    const m = /^\s*(--[\w-]+)\s*:\s*([\s\S]+?)\s*$/.exec(chunk)
    if (m) out.push({ name: m[1], value: m[2].replace(/\s+/g, ' ').replace(/\s*!important$/, ''), within: [...within] })
    chunk = ''
  }
  for (const ch of text) {
    if (quote) {
      chunk += ch
      if (ch === quote) quote = ''
      continue
    }
    if (ch === '"' || ch === "'") {
      quote = ch
      chunk += ch
    } else if (ch === '(') {
      depth++
      chunk += ch
    } else if (ch === ')') {
      depth = Math.max(0, depth - 1)
      chunk += ch
    } else if (ch === '{' && depth === 0) {
      within.push(chunk.trim().replace(/\s+/g, ' '))
      chunk = ''
    } else if (ch === '}' && depth === 0) {
      flush()
      within.pop()
    } else if (ch === ';' && depth === 0) {
      flush()
    } else {
      chunk += ch
    }
  }
  return out
}

const DARK = /prefers-color-scheme:\s*dark|data-(mode|theme|color-scheme)=["']?dark|\.dark\b/i
const LIGHT = /prefers-color-scheme:\s*light|data-(mode|theme|color-scheme)=["']?light|\.light\b/i
const NAMED = /data-theme=["']?([\w-]+)/i

/** Whether a declaration applies to the page being themed. */
function applies(d: Declaration, o: Required<Pick<StackmythThemeOptions, 'mode'>> & { theme?: string }): boolean {
  for (const scope of d.within) {
    if (o.mode === 'light' && DARK.test(scope)) return false
    if (o.mode === 'dark' && LIGHT.test(scope)) return false
    const named = NAMED.exec(scope)
    if (named && !/^(dark|light)$/i.test(named[1]) && named[1] !== o.theme) return false
    // Component-level rules (`.btn { --sm-… }`) are not the page's theme;
    // the class a mode is switched with (`.dark`, as shadcn/ui does) is.
    if (!scope.startsWith('@') && !/:root|^html\b|^body\b|\[data-|^\*$|:host|^\.(dark|light)\b/.test(scope)) return false
  }
  return true
}

// ── Tokens ─────────────────────────────────────────────────────────────────

/** What a token's value may be written with, as Cauthy checks it. */
const TOKEN_CHARS = /^[A-Za-z0-9 #%.,()/'"_+*-]+$/
const TOKEN_FUNCS = new Set(['var', 'calc', 'min', 'max', 'clamp', 'rgb', 'rgba', 'hsl', 'hsla', 'hwb', 'lab', 'lch', 'oklab', 'oklch', 'color',
  'color-mix', 'light-dark', 'cubic-bezier', 'steps', 'linear', 'linear-gradient', 'radial-gradient', 'conic-gradient',
  'repeating-linear-gradient', 'repeating-radial-gradient', 'drop-shadow', 'blur', 'translate', 'translatex', 'translatey', 'scale', 'rotate'])

function tokenValue(value: string): string | null {
  const v = value.replace(/\s+/g, ' ').trim()
  if (v === '' || v.length > 400 || !TOKEN_CHARS.test(v)) return null
  for (const m of v.matchAll(/([A-Za-z-]+)\(/g)) if (!TOKEN_FUNCS.has(m[1].toLowerCase())) return null
  if (/^\(|[ ,(]\(/.test(v)) return null
  return v
}

/** A scope that is the page's theme itself: the root, or the theme and mode attributes — never a component inside it. */
const THEME_SELECTOR = /^(?::root|html|body|\[data-(?:theme|mode|color-scheme)(?:=["']?[\w-]+["']?)?\])$/i
// Checked a selector at a time (split on commas and spaces) rather than with
// one pattern over the list, which backtracks on a long one.
const isThemeScope = (selectors: string) => {
  const parts = selectors.split(/[\s,]+/).filter(Boolean)
  return parts.length > 0 && parts.every((one) => THEME_SELECTOR.test(one))
}

export interface StackmythTokens {
  /** Every `--sm-*` token the stylesheets set for the page, ready for `theme.tokens`. */
  tokens: Record<string, string>
  /** Tokens that were there and Cauthy would not take, and why. */
  warnings: string[]
}

/**
 * Reads an application's Stackmyth tokens out of its stylesheets: every
 * `--sm-*` custom property its theme sets, in the order the sheets are given
 * (a later one wins). Its own names — a brand palette the tokens point at —
 * are written in, so what comes out stands on Stackmyth's names alone.
 *
 * Cauthy's sign-in pages are drawn with Stackmyth's components: these tokens
 * are what makes them look like the application.
 */
export function tokensFromStackmyth(css: string | string[], options: StackmythThemeOptions = {}): StackmythTokens {
  const mode = options.mode ?? 'light'
  const all = (Array.isArray(css) ? css : [css]).flatMap(declarations)
  const named = options.theme ?? all.map((d) => d.within.map((w) => NAMED.exec(w)?.[1]).find((n) => n && !/^(dark|light)$/i.test(n))).find(Boolean)
  const vars = new Map<string, string>()
  for (const d of all) {
    if (!applies(d, { mode, theme: named })) continue
    if (!d.within.every((w) => w.startsWith('@') || isThemeScope(w))) continue
    vars.set(d.name, d.value)
  }
  // The application's own names are written in; Stackmyth's are left as references.
  const inline = (value: string, depth = 0): string | null => {
    if (depth > 16) return null
    let failed = false
    let out = value
    for (let guard = 0; guard < 64; guard++) {
      const next = out.replace(/var\(\s*(--(?!sm-)[\w-]+)\s*(?:,\s*([^()]*(?:\([^()]*\)[^()]*)*))?\)/, (_m, name: string, fallback?: string) => {
        const known = vars.get(name)
        const got = known !== undefined ? inline(known, depth + 1) : fallback !== undefined ? inline(fallback.trim(), depth + 1) : null
        if (got === null) failed = true
        return got ?? ''
      })
      if (failed) return null
      if (next === out) break
      out = next
    }
    return out
  }
  const tokens: Record<string, string> = {}
  const warnings: string[] = []
  for (const [name, raw] of vars) {
    if (!/^--sm-[a-z0-9]+(?:-[a-z0-9]+)*$/.test(name)) continue
    const written = inline(raw)
    const value = written === null ? null : tokenValue(written)
    if (value === null) warnings.push(`${name}: "${raw.length > 60 ? raw.slice(0, 57) + '…' : raw}" is not a value Cauthy takes`)
    else tokens[name] = value
  }
  if (Object.keys(tokens).length === 0) warnings.push('no --sm-* token was found in these stylesheets')
  return { tokens, warnings }
}

// ── Values ─────────────────────────────────────────────────────────────────

function resolve(value: string, vars: Map<string, string>, seen = 0): string | null {
  if (seen > 16) return null
  let unresolved = false
  // Innermost var() first: fallbacks may hold another var().
  let out = value
  for (let guard = 0; guard < 32 && /var\(/.test(out); guard++) {
    out = out.replace(/var\(\s*(--[\w-]+)\s*(?:,\s*([^()]*(?:\([^()]*\)[^()]*)*))?\)/, (_m, name: string, fallback?: string) => {
      const known = vars.get(name)
      const next = known !== undefined ? resolve(known, vars, seen + 1) : fallback !== undefined ? resolve(fallback.trim(), vars, seen + 1) : null
      if (next === null) unresolved = true
      return next ?? ''
    })
    if (unresolved) return null
  }
  return /var\(/.test(out) ? null : out.trim()
}

const clamp01 = (n: number) => Math.min(1, Math.max(0, n))
const hex2 = (n: number) => Math.round(clamp01(n) * 255).toString(16).padStart(2, '0')
const gamma = (c: number) => (c <= 0.0031308 ? 12.92 * c : 1.055 * Math.pow(c, 1 / 2.4) - 0.055)

function out(r: number, g: number, b: number, a = 1): string {
  if (a >= 1) return `#${hex2(r)}${hex2(g)}${hex2(b)}`
  return `rgba(${Math.round(clamp01(r) * 255)}, ${Math.round(clamp01(g) * 255)}, ${Math.round(clamp01(b) * 255)}, ${Math.round(clamp01(a) * 1000) / 1000})`
}

const alpha = (s: string | undefined) => (s === undefined ? 1 : s.endsWith('%') ? parseFloat(s) / 100 : parseFloat(s))

const KEYWORDS: Record<string, string> = { white: '#ffffff', black: '#000000' }

/** A colour as Cauthy takes it — `#rrggbb` or `rgba(…)` — or null when it is none it can read. */
export function toColor(value: string): string | null {
  const v = value.trim().toLowerCase()
  if (KEYWORDS[v]) return KEYWORDS[v]
  if (/^#([0-9a-f]{3,4}|[0-9a-f]{6}|[0-9a-f]{8})$/.test(v)) return v
  let m = /^rgba?\(\s*([\d.]+%?)[\s,]+([\d.]+%?)[\s,]+([\d.]+%?)(?:\s*[,/]\s*([\d.]+%?))?\s*\)$/.exec(v)
  if (m) {
    const ch = (s: string) => (s.endsWith('%') ? parseFloat(s) / 100 : parseFloat(s) / 255)
    return out(ch(m[1]), ch(m[2]), ch(m[3]), alpha(m[4]))
  }
  m = /^hsla?\(\s*([\d.]+)(?:deg)?[\s,]+([\d.]+)%[\s,]+([\d.]+)%(?:\s*[,/]\s*([\d.]+%?))?\s*\)$/.exec(v)
  if (m) {
    const h = ((parseFloat(m[1]) % 360) + 360) % 360
    const s = parseFloat(m[2]) / 100
    const l = parseFloat(m[3]) / 100
    const f = (n: number) => {
      const k = (n + h / 30) % 12
      return l - s * Math.min(l, 1 - l) * Math.max(-1, Math.min(k - 3, 9 - k, 1))
    }
    return out(f(0), f(8), f(4), alpha(m[4]))
  }
  m = /^oklch\(\s*([\d.]+%?)\s+([\d.]+%?)\s+([\d.]+)(?:deg)?(?:\s*\/\s*([\d.]+%?))?\s*\)$/.exec(v)
  if (m) {
    const L = m[1].endsWith('%') ? parseFloat(m[1]) / 100 : parseFloat(m[1])
    const C = m[2].endsWith('%') ? (parseFloat(m[2]) / 100) * 0.4 : parseFloat(m[2])
    const H = (parseFloat(m[3]) * Math.PI) / 180
    const a = C * Math.cos(H)
    const b = C * Math.sin(H)
    const l = Math.pow(L + 0.3963377774 * a + 0.2158037573 * b, 3)
    const mm = Math.pow(L - 0.1055613458 * a - 0.0638541728 * b, 3)
    const s = Math.pow(L - 0.0894841775 * a - 1.291485548 * b, 3)
    return out(
      gamma(4.0767416621 * l - 3.3077115913 * mm + 0.2309699292 * s),
      gamma(-1.2684380046 * l + 2.6097574011 * mm - 0.3413193965 * s),
      gamma(-0.0041960863 * l - 0.7034186147 * mm + 1.707614701 * s),
      alpha(m[4]),
    )
  }
  return null
}

/** A length in pixels, within what Cauthy takes, or null. */
function toRadius(value: string): number | null {
  const m = /^([\d.]+)(px|rem|em)?$/.exec(value.trim())
  if (!m) return null
  const px = parseFloat(m[1]) * (m[2] === 'rem' || m[2] === 'em' ? 16 : 1)
  return Number.isFinite(px) ? Math.min(MAX_RADIUS, Math.max(0, Math.round(px))) : null
}

/** A font list as Cauthy takes it, or null. */
function toFont(value: string): string | null {
  const v = value.trim()
  return /^[A-Za-z0-9 ,'"_-]{1,200}$/.test(v) && (v.match(/"/g)?.length ?? 0) % 2 === 0 && (v.match(/'/g)?.length ?? 0) % 2 === 0 ? v : null
}

// ── Stackmyth ──────────────────────────────────────────────────────────────

/** Which Stackmyth token each value of a theme is read from, first found wins. */
const COLORS: [keyof CauthyTheme, string[]][] = [
  ['background', ['--sm-bg-surface', '--sm-surface']],
  ['surface', ['--sm-bg-surface-raised', '--sm-surface-raised']],
  ['text', ['--sm-text-primary', '--sm-surface-text']],
  ['textMuted', ['--sm-text-secondary']],
  ['border', ['--sm-border-default', '--sm-surface-border']],
  ['primary', ['--sm-primary', '--sm-bg-interactive']],
  ['primaryText', ['--sm-primary-text', '--sm-text-inverse']],
  ['accent', ['--sm-text-brand', '--sm-border-focus', '--sm-accent']],
  ['error', ['--sm-error-soft-text', '--sm-error']],
  ['errorBackground', ['--sm-error-soft']],
  ['success', ['--sm-success-soft-text', '--sm-success']],
  ['successBackground', ['--sm-success-soft']],
]

/**
 * Reads an application's Stackmyth theme out of its stylesheets.
 *
 * Give it the CSS that declares the tokens, in the order the application
 * loads it — Stackmyth's own (`@stackmyth/core/core.vars.css`, or a theme
 * file) and then the application's brand file that re-points them. Tokens
 * that point at the application's own variables are followed. The
 * application's dark mode is left out unless asked for.
 */
export function themeFromStackmyth(css: string | string[], options: StackmythThemeOptions = {}): ImportedTheme {
  const o = { mode: options.mode ?? 'light', theme: options.theme }
  const vars = new Map<string, string>()
  for (const sheet of Array.isArray(css) ? css : [css]) {
    for (const d of declarations(sheet)) if (applies(d, o)) vars.set(d.name, d.value)
  }
  const theme: CauthyTheme = {}
  const warnings: string[] = []

  const read = <T>(tokens: string[], to: (v: string) => T | null, what: string): T | undefined => {
    for (const token of tokens) {
      const raw = vars.get(token)
      if (raw === undefined) continue
      const value = resolve(raw, vars)
      const got = value === null ? null : to(value)
      if (got !== null) return got
      warnings.push(`${token}: "${raw}" is not ${what} Cauthy can take`)
    }
    return undefined
  }

  for (const [field, tokens] of COLORS) {
    const c = read(tokens, toColor, 'a colour')
    if (c !== undefined) (theme as Record<string, unknown>)[field] = c
  }
  const radius = read(['--sm-radius-container', '--sm-radius-md'], toRadius, 'a length')
  if (radius !== undefined) theme.radius = radius
  const button = read(['--sm-radius-interactive', '--sm-radius-sm'], toRadius, 'a length')
  if (button !== undefined) theme.buttonRadius = button
  const font = read(['--sm-font-family'], toFont, 'a font list')
  if (font !== undefined) theme.fontFamily = font
  if (options.logoUrl) theme.logoUrl = options.logoUrl

  if (vars.size === 0) warnings.push('no custom properties were found: is this the stylesheet that declares the --sm-* tokens?')
  else if (![...vars.keys()].some((k) => k.startsWith('--sm-'))) warnings.push('no --sm-* token was found in these stylesheets')
  return { theme, warnings }
}

// ── Any stylesheet ─────────────────────────────────────────────────────────

/** The values of a theme a stylesheet can say. */
export type ThemeField =
  | 'background' | 'surface' | 'text' | 'textMuted' | 'border' | 'inputBackground' | 'inputBorder'
  | 'primary' | 'primaryText' | 'accent' | 'error' | 'errorBackground' | 'success' | 'successBackground'
  | 'radius' | 'buttonRadius' | 'fontFamily'

/** How a stylesheet names its look: Stackmyth's tokens, shadcn/ui's (and Tailwind's), or the application's own. */
export type CssFormat = 'stackmyth' | 'shadcn' | 'custom'

export interface CssThemeOptions {
  /** Which names to read. Default: `auto`, told from the stylesheet itself. */
  format?: CssFormat | 'auto'
  /** Which of the application's two modes to take. Default: `light`. */
  mode?: 'light' | 'dark'
  /** The named theme to read, when the stylesheet keeps several under `[data-theme=…]`. */
  theme?: string
  /** For `custom`: the variable each value is read from, `{ primary: '--brand' }`. */
  map?: Partial<Record<ThemeField, string>>
}

export interface CssImportedTheme extends ImportedTheme {
  /** The names that were read. */
  format: CssFormat
}

const RADII: ThemeField[] = ['radius', 'buttonRadius']

/** shadcn/ui's names, as Tailwind 3 (`--primary`) and Tailwind 4 (`--color-primary`) write them. */
const SHADCN: [ThemeField, string[]][] = [
  ['background', ['--background', '--color-background']],
  ['surface', ['--card', '--color-card', '--popover', '--color-popover']],
  ['text', ['--foreground', '--color-foreground']],
  ['textMuted', ['--muted-foreground', '--color-muted-foreground']],
  ['border', ['--border', '--color-border']],
  ['inputBorder', ['--input', '--color-input']],
  ['primary', ['--primary', '--color-primary']],
  ['primaryText', ['--primary-foreground', '--color-primary-foreground']],
  ['accent', ['--ring', '--color-ring', '--primary', '--color-primary']],
  ['error', ['--destructive', '--color-destructive']],
  ['radius', ['--radius']],
  ['buttonRadius', ['--radius']],
  ['fontFamily', ['--font-sans', '--font-family']],
]

/** A colour as shadcn/ui writes it on Tailwind 3 — `222.2 84% 4.9%`, the inside of hsl() — or any other. */
function shadcnColor(value: string): string | null {
  return /^[\d.]+(?:deg)?\s+[\d.]+%\s+[\d.]+%(?:\s*\/\s*[\d.]+%?)?$/.test(value.trim()) ? toColor(`hsl(${value.trim()})`) : toColor(value)
}

/** Every custom property a stylesheet sets for the page, the last one winning. */
function pageVariables(css: string | string[], mode: 'light' | 'dark', theme?: string): Map<string, string> {
  const vars = new Map<string, string>()
  for (const sheet of Array.isArray(css) ? css : [css]) {
    for (const d of declarations(sheet)) if (applies(d, { mode, theme })) vars.set(d.name, d.value)
  }
  return vars
}

/** The custom properties a stylesheet sets for the page, by name: what a person picks from to map their own. */
export function cssVariables(css: string | string[], options: Pick<CssThemeOptions, 'mode' | 'theme'> = {}): string[] {
  return [...pageVariables(css, options.mode ?? 'light', options.theme).keys()].sort()
}

/**
 * Reads an application's look out of its stylesheets, whatever names it uses:
 * Stackmyth's tokens, shadcn/ui's (`--primary`, `--radius`, on Tailwind 3 or
 * 4), or the application's own variables given in `map`. What comes out is a
 * theme of named values, never CSS.
 */
export function themeFromCss(css: string | string[], options: CssThemeOptions = {}): CssImportedTheme {
  const mode = options.mode ?? 'light'
  const vars = pageVariables(css, mode, options.theme)
  const names = [...vars.keys()]
  let format: CssFormat
  if (options.format && options.format !== 'auto') format = options.format
  else if (options.map && Object.keys(options.map).length > 0) format = 'custom'
  else if (names.some((n) => n.startsWith('--sm-'))) format = 'stackmyth'
  else if (names.some((n) => /^--(color-)?(primary|background|foreground)$/.test(n))) format = 'shadcn'
  else format = 'custom'

  if (format === 'stackmyth') return { ...themeFromStackmyth(css, { mode, theme: options.theme }), format }

  const spec: [ThemeField, string[]][] = format === 'shadcn'
    ? SHADCN
    : Object.entries(options.map ?? {}).filter(([, v]) => v).map(([k, v]) => [k as ThemeField, [String(v).startsWith('--') ? String(v) : `--${v}`]])
  const theme: CauthyTheme = {}
  const warnings: string[] = []
  for (const [field, tokens] of spec) {
    for (const token of tokens) {
      const raw = vars.get(token)
      if (raw === undefined) continue
      const value = resolve(raw, vars)
      const got = value === null ? null
        : RADII.includes(field) ? toRadius(value)
        : field === 'fontFamily' ? toFont(value)
        : format === 'shadcn' ? shadcnColor(value) : toColor(value)
      if (got !== null) {
        (theme as Record<string, unknown>)[field] = got
        break
      }
      warnings.push(`${token}: "${raw.length > 60 ? raw.slice(0, 57) + '…' : raw}" is not ${RADII.includes(field) ? 'a length' : field === 'fontFamily' ? 'a font list' : 'a colour'} Cauthy can take`)
    }
  }
  if (vars.size === 0) warnings.push('no custom properties were found in these stylesheets')
  else if (format === 'custom' && spec.length === 0) warnings.push('these stylesheets use names of their own: say which variable each value is read from')
  return { theme, warnings, format }
}

// ── On the application's own screens ───────────────────────────────────────

/**
 * A theme as the CSS variables of `@cauthyhq/node/styles.css` (`--cauthy-*`), for
 * the forms an application shows on its own pages. The page's own background,
 * the layout and the words are Cauthy's pages' matter, and left out.
 */
export function themeVariables(theme: CauthyTheme): Record<string, string> {
  const vars: Record<string, string> = {}
  const put = (name: string, v: string | number | undefined) => {
    if (v === undefined || v === '') return
    vars[`--cauthy-${name}`] = typeof v === 'number' ? `${v}px` : v
  }
  put('surface', theme.surface)
  put('text', theme.text)
  put('text-muted', theme.textMuted)
  put('border', theme.border)
  put('input-background', theme.inputBackground)
  put('input-border', theme.inputBorder)
  put('primary', theme.primary)
  put('primary-text', theme.primaryText)
  put('accent', theme.accent)
  put('error', theme.error)
  put('error-background', theme.errorBackground)
  put('success', theme.success)
  put('success-background', theme.successBackground)
  put('radius', theme.radius)
  put('button-radius', theme.buttonRadius)
  put('font', theme.fontFamily)
  return vars
}

// ── Sending it to Cauthy ───────────────────────────────────────────────────

/** A theme as Cauthy's API names its values. */
export function toWire(theme: CauthyTheme): Record<string, unknown> {
  const names: Record<keyof CauthyTheme, string> = {
    background: 'background', surface: 'surface', text: 'text', textMuted: 'text_muted', border: 'border',
    primary: 'primary', primaryText: 'primary_text', accent: 'accent', error: 'error', errorBackground: 'error_background',
    success: 'success', successBackground: 'success_background', radius: 'radius', buttonRadius: 'button_radius',
    fontFamily: 'font_family', logoUrl: 'logo_url', fonts: 'fonts', layout: 'layout', panelColors: 'panel_colors',
    panelText: 'panel_text', panelIconUrl: 'panel_icon_url', texts: 'texts', inputBackground: 'input_background', inputBorder: 'input_border', tokens: 'tokens',
  }
  const wire: Record<string, unknown> = {}
  for (const [k, v] of Object.entries(theme)) {
    if (v === undefined || v === '' || (Array.isArray(v) && v.length === 0)) continue
    wire[names[k as keyof CauthyTheme]] = v
  }
  return wire
}

/** A theme as Cauthy answers it, in this package's names. */
export function fromWire(wire: Record<string, unknown>): CauthyTheme {
  const names: Record<string, keyof CauthyTheme> = {
    background: 'background', surface: 'surface', text: 'text', text_muted: 'textMuted', border: 'border',
    primary: 'primary', primary_text: 'primaryText', accent: 'accent', error: 'error', error_background: 'errorBackground',
    success: 'success', success_background: 'successBackground', radius: 'radius', button_radius: 'buttonRadius',
    font_family: 'fontFamily', logo_url: 'logoUrl', fonts: 'fonts', layout: 'layout', panel_colors: 'panelColors',
    panel_text: 'panelText', panel_icon_url: 'panelIconUrl', texts: 'texts', input_background: 'inputBackground', input_border: 'inputBorder', tokens: 'tokens',
  }
  const theme: Record<string, unknown> = {}
  for (const [k, v] of Object.entries(wire ?? {})) if (names[k] && v !== undefined && v !== null && v !== '') theme[names[k]] = v
  return theme as CauthyTheme
}

export interface PushThemeOptions {
  /** Cauthy's address. Default: `CAUTHY_ISSUER`. */
  issuer?: string
  /** The application's client id. Default: `CAUTHY_CLIENT_ID`. */
  clientId?: string
  /** The workspace's slug. Default: `CAUTHY_TENANT`. */
  tenant?: string
  /**
   * A personal access token with `oauth_clients:manage`. Default:
   * `CAUTHY_TOKEN`. It belongs in the deploy pipeline, never in the application.
   */
  token?: string
  theme: CauthyTheme
  fetch?: typeof fetch
}

/**
 * Gives the application its look on Cauthy's pages. It replaces the theme: a
 * value left out goes back to Cauthy's own. Run it when the brand changes —
 * from a script or the deploy — not on every request.
 */
export async function pushTheme(o: PushThemeOptions): Promise<void> {
  const env = (n: string) => (typeof process !== 'undefined' ? process.env?.[n] : undefined)
  const issuer = withoutTrailingSlashes(o.issuer ?? env('CAUTHY_ISSUER') ?? '')
  const clientId = o.clientId ?? env('CAUTHY_CLIENT_ID') ?? ''
  const tenant = o.tenant ?? env('CAUTHY_TENANT') ?? ''
  const token = o.token ?? env('CAUTHY_TOKEN') ?? ''
  for (const [name, v] of Object.entries({ CAUTHY_ISSUER: issuer, CAUTHY_CLIENT_ID: clientId, CAUTHY_TENANT: tenant, CAUTHY_TOKEN: token })) {
    if (v === '') throw new Error(`@cauthyhq/node: ${name} is required to push a theme`)
  }
  const res = await (o.fetch ?? fetch)(`${issuer}/v1/oauth/clients/${encodeURIComponent(clientId)}/theme`, {
    method: 'PUT',
    headers: { authorization: `Bearer ${token}`, 'x-tenant-key': tenant, 'content-type': 'application/json' },
    body: JSON.stringify(toWire(o.theme)),
  })
  if (!res.ok) {
    const body = (await res.json().catch(() => null)) as { errors?: { message?: string }[] } | null
    throw new Error(`@cauthyhq/node: Cauthy refused the theme (${res.status}): ${body?.errors?.[0]?.message ?? res.statusText}`)
  }
}
