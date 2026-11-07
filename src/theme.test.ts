import { describe, expect, it } from 'vitest'
import { cssVariables, pushTheme, themeFromCss, themeFromStackmyth, themeVariables, toColor, toWire, tokensFromStackmyth } from './theme'

// A Stackmyth theme file, as the library ships them.
const STACKMYTH = `
@layer themes {
  [data-theme=acme] {
    --sm-font-family: "Outfit", system-ui, sans-serif;
    --sm-bg-interactive: #0F1113;
    --sm-text-inverse: #ffffff;
    --sm-border-focus: #00AEEF;
    --sm-bg-surface: #FDFDFC;
    --sm-bg-surface-raised: #F2F4F5;
    --sm-border-default: #E4E2DC;
    --sm-text-primary: #0F1113;
    --sm-text-secondary: #2C3234;
    --sm-text-brand: #0E7C9E;
    --sm-primary: var(--sm-bg-interactive);
    --sm-primary-text: var(--sm-text-inverse);
    --sm-error-soft: #F7ECEA;
    --sm-error-soft-text: #C4342B;
    --sm-radius-sm: 10px;
    --sm-radius-md: 16px;
    --sm-radius-full: 9999px;
    --sm-radius-interactive: var(--sm-radius-full);
    --sm-radius-container: var(--sm-radius-md);
    --sm-shadow-md:
      rgba(15, 17, 19, 0.05) 0px 1px 2px 0px,
      rgba(15, 17, 19, 0.08) 0px 20px 50px 0px;
  }
  [data-theme=graphite] { --sm-bg-surface: #111111; --sm-text-primary: #eeeeee; }
}`

// Stackmyth's defaults, and an application's brand file re-pointing them at
// its own variables, with a dark mode — the way a real application does it.
const CORE = `:root { --sm-bg-surface: #ffffff; --sm-text-primary: #18181b; --sm-radius-md: 0.5rem; --sm-radius-container: var(--sm-radius-md);
  --sm-font-family: system-ui, sans-serif; --sm-primary: var(--sm-bg-interactive); --sm-bg-interactive: #18181b; }`
const BRAND = `
/* the palette; { braces } in a comment change nothing */
:root {
  --app-paper: oklch(0.985 0.005 75);
  --app-ink: hsl(30 12% 8%);
  --app-action: #E8590C;
  --app-line: rgb(15 17 19 / 8%);
  --sm-bg-surface: var(--app-paper);
  --sm-text-primary: var(--app-ink);
  --sm-bg-interactive: var(--app-action);
  --sm-text-inverse: white;
  --sm-border-default: var(--app-line);
  --sm-text-secondary: var(--app-missing, #555555);
  --sm-text-brand: color-mix(in oklab, red, blue);
  --sm-success-soft-text: var(--nowhere);
}
@media (prefers-color-scheme: dark) { :root { --app-paper: #0b0b0b; --app-ink: #fafafa; } }
[data-mode="dark"] { --app-paper: #0b0b0b; --app-ink: #fafafa; --app-action: #ff8a4c; }
.button { --sm-bg-interactive: #00ff00; }
`

describe('reading a Stackmyth theme', () => {
  it('takes the named theme of a Stackmyth theme file', () => {
    const { theme, warnings } = themeFromStackmyth(STACKMYTH, { theme: 'acme', logoUrl: 'https://cdn.example.com/logo.svg' })
    expect(theme).toEqual({
      background: '#fdfdfc', surface: '#f2f4f5', text: '#0f1113', textMuted: '#2c3234', border: '#e4e2dc',
      primary: '#0f1113', primaryText: '#ffffff', accent: '#0e7c9e', error: '#c4342b', errorBackground: '#f7ecea',
      radius: 16, buttonRadius: 40, // a pill, as round as Cauthy goes
      fontFamily: '"Outfit", system-ui, sans-serif', logoUrl: 'https://cdn.example.com/logo.svg',
    })
    expect(warnings).toEqual([])
    // Another theme of the same file is another look; no name, no named theme.
    expect(themeFromStackmyth(STACKMYTH, { theme: 'graphite' }).theme).toEqual({ background: '#111111', text: '#eeeeee' })
    expect(themeFromStackmyth(STACKMYTH).theme).toEqual({})
  })

  it("follows an application's own variables, in the order its sheets load", () => {
    const { theme, warnings } = themeFromStackmyth([CORE, BRAND])
    expect(theme.background).toBe('#fcfaf6') // oklch, read as the colour it is
    expect(theme.text).toBe('#171412') // hsl
    expect(theme.primary).toBe('#e8590c') // the brand's, not the default nor a component's
    expect(theme.primaryText).toBe('#ffffff')
    expect(theme.border).toBe('rgba(15, 17, 19, 0.08)')
    expect(theme.textMuted).toBe('#555555') // the fallback of a variable that is not there
    expect(theme.radius).toBe(8) // 0.5rem
    expect(theme.fontFamily).toBe('system-ui, sans-serif')
    // What cannot be carried over is said, and left to Cauthy's own.
    expect(theme.accent).toBeUndefined()
    expect(theme.success).toBeUndefined()
    expect(warnings).toHaveLength(2)
    expect(warnings.join(' ')).toMatch(/--sm-text-brand.*--sm-success-soft-text/)
  })

  it("takes the application's dark mode when asked", () => {
    const dark = themeFromStackmyth([CORE, BRAND], { mode: 'dark' }).theme
    expect(dark.background).toBe('#0b0b0b')
    expect(dark.text).toBe('#fafafa')
    expect(dark.primary).toBe('#ff8a4c')
  })

  it('says so when the stylesheet is not the one', () => {
    expect(themeFromStackmyth('body { color: red }').warnings[0]).toMatch(/no custom properties/)
    expect(themeFromStackmyth(':root { --brand: #fff }').warnings[0]).toMatch(/no --sm-\* token/)
  })

  it('reads colours in the notations stylesheets use', () => {
    expect(toColor('#FFF')).toBe('#fff')
    expect(toColor('rgb(255, 0, 0)')).toBe('#ff0000')
    expect(toColor('rgba(0, 0, 0, 0.5)')).toBe('rgba(0, 0, 0, 0.5)')
    expect(toColor('hsl(0, 100%, 50%)')).toBe('#ff0000')
    expect(toColor('oklch(1 0 0)')).toBe('#ffffff')
    expect(toColor('oklch(0.628 0.2577 29.23)')).toBe('#ff0000')
    expect(toColor('transparent')).toBeNull()
    expect(toColor('url(x)')).toBeNull()
  })
})

describe('sending a theme to Cauthy', () => {
  it('names the values as the API does and replaces the theme', async () => {
    const calls: { url: string; init: RequestInit }[] = []
    const fake: typeof fetch = async (url, init) => {
      calls.push({ url: String(url), init: init! })
      return new Response('{}', { status: 200 })
    }
    await pushTheme({ issuer: 'https://id.test/', clientId: 'client_app', tenant: 'acme', token: 'cpat_x', fetch: fake,
      theme: { primary: '#e8590c', textMuted: '#555555', buttonRadius: 40, fontFamily: 'Outfit, sans-serif', logoUrl: 'https://x.test/l.svg' } })
    expect(calls[0].url).toBe('https://id.test/v1/oauth/clients/client_app/theme')
    expect(calls[0].init.method).toBe('PUT')
    expect(new Headers(calls[0].init.headers).get('x-tenant-key')).toBe('acme')
    expect(JSON.parse(String(calls[0].init.body))).toEqual({ primary: '#e8590c', text_muted: '#555555', button_radius: 40,
      font_family: 'Outfit, sans-serif', logo_url: 'https://x.test/l.svg' })
    expect(toWire({})).toEqual({})
  })

  it('says what Cauthy refused, and what is missing', async () => {
    const refuse: typeof fetch = async () =>
      new Response(JSON.stringify({ errors: [{ code: 'invalid_theme', message: 'primary must be a colour' }] }), { status: 400 })
    await expect(pushTheme({ issuer: 'https://id.test', clientId: 'c', tenant: 't', token: 'k', theme: {}, fetch: refuse })).rejects.toThrow(/primary must be a colour/)
    await expect(pushTheme({ issuer: 'https://id.test', clientId: 'c', tenant: 't', token: '', theme: {} })).rejects.toThrow(/CAUTHY_TOKEN/)
  })
})

describe('an application\'s Stackmyth tokens', () => {
  const palette = `[data-theme='acme'] [data-mode='light'] { --acme-blue: #3d5afe; --acme-ink: #0b0d17; }
    [data-theme='acme'] [data-mode='dark'] { --acme-blue: #8fa2ff; }`
  const sheet = `@layer themes {
      [data-theme='acme'], [data-theme='acme'] [data-mode='light'] {
        --sm-bg-interactive: var(--acme-blue);
        --sm-text-primary: var(--acme-ink);
        --sm-radius-sm: 6px;
        --sm-shadow-sm: color-mix(in srgb, var(--acme-ink) 3%, transparent) 0px 1px 2px 0px;
      }
      [data-theme='acme'] [data-mode='dark'] { --sm-bg-interactive: #000000; }
      [data-theme='other'] { --sm-radius-sm: 99px; }
    }
    [data-theme='acme'] {
      --sm-control-elevation: inset 0 -2px 0 color-mix(in srgb, var(--sm-text-primary) 12%, transparent);
      --sm-button-elevation: var(--sm-control-elevation);
      --sm-font-family: 'DM Sans', system-ui, sans-serif;
      --sm-grain: url("data:image/svg+xml,x");
      --acme-only: 1px;
    }
    [data-theme='acme'] .sm-select { --sm-radius-sm: 40px; }`

  it('are read whole, with the application\'s own names written in', async () => {
    const { tokensFromStackmyth } = await import('./theme')
    const { tokens, warnings } = tokensFromStackmyth([palette, sheet])
    expect(tokens).toEqual({
      '--sm-bg-interactive': '#3d5afe', // the light one, through the palette
      '--sm-text-primary': '#0b0d17',
      '--sm-radius-sm': '6px', // not another theme's, not a component's
      '--sm-shadow-sm': 'color-mix(in srgb, #0b0d17 3%, transparent) 0px 1px 2px 0px',
      // Stackmyth's own names stay references: the page resolves them.
      '--sm-control-elevation': 'inset 0 -2px 0 color-mix(in srgb, var(--sm-text-primary) 12%, transparent)',
      '--sm-button-elevation': 'var(--sm-control-elevation)',
      '--sm-font-family': "'DM Sans', system-ui, sans-serif",
    })
    // What would make the page fetch is left out, and said.
    expect(warnings).toEqual([expect.stringContaining('--sm-grain')])
    expect(tokensFromStackmyth([palette, sheet], { mode: 'dark' }).tokens['--sm-bg-interactive']).toBe('#000000')
    expect(tokensFromStackmyth('body { color: red }').warnings).toEqual(['no --sm-* token was found in these stylesheets'])
  })
})

describe('any application\'s stylesheet', () => {
  // shadcn/ui on Tailwind 3: colours are the inside of hsl().
  const shadcn3 = `
    @layer base {
      :root {
        --background: 0 0% 100%;
        --foreground: 222.2 84% 4.9%;
        --card: 0 0% 100%;
        --muted-foreground: 215.4 16.3% 46.9%;
        --border: 214.3 31.8% 91.4%;
        --input: 214.3 31.8% 91.4%;
        --primary: 221.2 83.2% 53.3%;
        --primary-foreground: 210 40% 98%;
        --destructive: 0 84.2% 60.2%;
        --ring: 221.2 83.2% 53.3%;
        --radius: 0.5rem;
      }
      .dark { --background: 222.2 84% 4.9%; --primary: 217.2 91.2% 59.8%; }
    }`
  // shadcn/ui on Tailwind 4: oklch() colours, and @theme pointing at them.
  const shadcn4 = `
    :root { --radius: 0.625rem; --background: oklch(1 0 0); --foreground: oklch(0.145 0 0); --primary: oklch(0.205 0 0); --primary-foreground: oklch(0.985 0 0); }
    .dark { --background: oklch(0.145 0 0); }
    @theme inline { --color-background: var(--background); --font-sans: "Geist", system-ui, sans-serif; }`

  it('reads shadcn/ui on Tailwind 3, light mode', () => {
    const { theme, format, warnings } = themeFromCss(shadcn3)
    expect(format).toBe('shadcn')
    expect(warnings).toEqual([])
    expect(theme).toMatchObject({ background: '#ffffff', text: '#020817', primary: '#2563eb', primaryText: '#f8fafc', accent: '#2563eb', error: '#ef4444', radius: 8, buttonRadius: 8 })
    expect(themeFromCss(shadcn3, { mode: 'dark' }).theme.background).toBe('#020817')
  })

  it('reads shadcn/ui on Tailwind 4', () => {
    const { theme, format } = themeFromCss(shadcn4)
    expect(format).toBe('shadcn')
    expect(theme).toMatchObject({ background: '#ffffff', primary: '#171717', primaryText: '#fafafa', radius: 10, fontFamily: '"Geist", system-ui, sans-serif' })
  })

  it('reads the application\'s own names, as it maps them', () => {
    const own = `:root { --brand: #3d5afe; --brand-ink: white; --paper: #fafaf7; --corner: 12px; }`
    expect(cssVariables(own)).toEqual(['--brand', '--brand-ink', '--corner', '--paper'])
    const asIs = themeFromCss(own)
    expect(asIs.format).toBe('custom')
    expect(asIs.warnings[0]).toMatch(/say which variable/)
    const mapped = themeFromCss(own, { map: { primary: '--brand', primaryText: 'brand-ink', background: '--paper', radius: '--corner' } })
    expect(mapped.theme).toEqual({ primary: '#3d5afe', primaryText: '#ffffff', background: '#fafaf7', radius: 12 })
  })

  it('still reads Stackmyth\'s tokens, told apart by their names', () => {
    expect(themeFromCss(':root { --sm-bg-interactive: #112233; }').format).toBe('stackmyth')
  })

  it('says what it could not take', () => {
    const { theme, warnings } = themeFromCss(':root { --primary: url(x.png); --radius: 1rem; }')
    expect(theme).toEqual({ radius: 16, buttonRadius: 16 })
    expect(warnings.join()).toMatch(/--primary.*not a colour/)
  })
})

describe('a theme on the application\'s own forms', () => {
  it('becomes the --cauthy-* variables of styles.css, without the page\'s own matters', () => {
    expect(themeVariables({ primary: '#112233', radius: 4, fontFamily: 'Inter, sans-serif', background: '#000000', layout: 'split' })).toEqual({
      '--cauthy-primary': '#112233', '--cauthy-radius': '4px', '--cauthy-font': 'Inter, sans-serif',
    })
  })
})

describe('reading the theme out of long or odd stylesheets', () => {
  it('reads past comments, closed or not, and keeps quick on a long run of them', () => {
    const css = ':root { /* a */ --sm-color-accent: #123456; /* b */ }\n' + '/*'.repeat(20000)
    const started = Date.now()
    const { tokens } = tokensFromStackmyth(css)
    expect(tokens['--sm-color-accent']).toBe('#123456')
    expect(Date.now() - started).toBeLessThan(500)
  })

  it('takes a list of root selectors, and not a component inside them', () => {
    expect(tokensFromStackmyth(':root, html { --sm-color-text: #111; }').tokens['--sm-color-text']).toBe('#111')
    expect(tokensFromStackmyth('.card { --sm-color-text: #111; }').tokens['--sm-color-text']).toBeUndefined()
    expect(tokensFromStackmyth(':root .card { --sm-color-text: #111; }').tokens['--sm-color-text']).toBeUndefined()
  })
})
