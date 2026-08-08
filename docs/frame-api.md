# The frame API

Reference for `/api/frame/*`, the undocumented API behind Claude Code artifacts. Derived from
the Claude Code binary 2.1.222, re-verified against 2.1.223, and from the claude.ai artifact
viewer bundles, on 2026-08-05 and 06.

**How to read this.** Unmarked statements were observed: read directly in code, or seen in a live
response. Two weaker tiers are called out where they occur, as *Read but not observed* (present in
the bundle, never exercised) and *Unknown* (with the experiment that would settle it). The closing
section lists everything still unverified. That distinction is the point of this document; an API
you cannot see the source of is worth exactly as much as your record of how you learned it.

**Expect drift.** Minified symbols rotate every release and lane selection is a server-flippable
gate. The durable anchors are string literals: `/api/frame/deploy/direct`, `X-Frame-CP`,
`tengu_cobalt_plinth_direct`.

---

## The model

Artifacts are called *frames* internally. A frame is a deployable object with a lifecycle API,
addressed by a UUID slug, carrying a permission record and an append-only version history.

Three URLs matter and they are not interchangeable.

```
https://claude.ai/code/artifact/<slug>                    the viewer: chrome, byline, Report button
https://<slug>.frame.claudeusercontent.com/_f/<version>/  the content origin: your raw HTML
https://claude.ai/public/artifacts/<uuid>                 a different product entirely
```

The viewer URL is never returned by the API. The client builds it from the slug.

That third URL causes real confusion, so: chat artifacts and Code frames share no namespace, auth
surface, URL space, or permission model. They merely both produce a public link. The main claude.ai
SPA contains zero occurrences of `/code/artifact`, and the CLI bundle contains zero of
`/public/artifacts`. Two disjoint codebases.

---

## Auth

Your claude.ai OAuth login, not an API key. Nothing shows `/api/frame/*` accepting `x-api-key`.

Resolution order, matching the CLI: `CLAUDE_CODE_OAUTH_TOKEN`, then the macOS Keychain (service
`Claude Code-credentials`, account `$USER`, JSON path `claudeAiOauth.accessToken`), then
`<config dir>/.credentials.json`. The Keychain service name is computed rather than fixed: with
`CLAUDE_CONFIG_DIR` or `CLAUDE_SECURESTORAGE_CONFIG_DIR` set it becomes
`Claude Code-credentials-<sha256(dir)[:8]>`.

Every request carries six headers:

```
Authorization: Bearer <access token>
anthropic-beta: oauth-2025-04-20
X-Frame-CP: go
X-Frame-Surface: code
X-Frame-Platform: cli          "desktop" in the desktop app
```

The `X-Frame-*` trio is load bearing. `GET /api/frame/frames` returns 404 for every auth state
when they are omitted, and 200 with them, so **a 404 on this API is not evidence that a route is
absent**. Treat 405 as the reliable existence signal.

Access tokens live about 100 minutes; refresh tokens about 9.3 days. Every CLI frame call passes
`refreshOAuth:true` for that reason. A client that reads the Keychain once and caches the bearer
works this afternoon and fails tomorrow. Refresh is `POST <base>/v1/oauth/token` with
`{grant_type:"refresh_token", refresh_token, client_id}`, client id
`9d1c250a-e61b-44d9-88ed-5944d1962f5e`, at `expiresAt` minus 30 seconds.

Granted scopes are `user:profile`, `user:inference`, `user:sessions:claude_code`,
`user:mcp_servers`, `user:file_upload`. Nothing chat related, and nothing share related.

---

## Publishing

```
POST /api/frame/deploy/direct  →  {slug, version, read, shared}
```

The body is assembled from four builders plus content. The seven fields most clients need are
`title`, `favicon` and `content` (required), then `slug` to redeploy in place, and optionally
`description` (≤1000), `label` (≤60) and `entrypoint`.

The full set is larger than that, and two entries deserve attention. `session_id` means **every
publish transmits your session id** when `CLAUDE_CODE_REMOTE_SESSION_ID` is set. `publish_context`
is gated behind `tengu_frame_publish_context`, which is currently on, so it is on the wire today.
The rest: `template`, `auto_edit_attribution`, `contract`, `capabilities`, `force`, `baseVersion`,
and for the multi-file lane `files`, `manifest` and `mode`, which replaces `content` rather than
accompanying it.

The server allowlists body fields. The CLI carries a matcher for the resulting 400,
`/unknown field|not a recognized|not allowlisted/i`. This settles a tempting shortcut: you cannot
smuggle `{"read":{"mode":"public"}}` into a deploy. Visibility is always a separate request.

### The composed document

`content` is not your file. The client wraps it first, and a compatible client must reproduce this
byte for byte:

```html
<!doctype html><html><head><meta charset=utf8><meta name=viewport content="width=device-width,initial-scale=1"><style>:root{color-scheme:light}body{margin:0;padding:0;font:14px -apple-system,BlinkMacSystemFont,sans-serif;background:#faf9f5;color:#141413}img{max-width:100%}</style></head><body>
{your content}
</body></html>
```

There is deliberately no `<title>`: the title travels as a body field. A `lang` attribute appears
when `tengu_cobalt_plinth_laurel` is on, which it currently is not.

The CLI also sanitises your HTML before composing, which this client does not. It strips
a leading `<!-- frame-runtime -->` block (only when it begins within the first 8192 bytes and spans
under 300,000), `<base href="/_f/…">` tags, `data-frame-runtime` attributes, and two further
marker-delimited excisions. Its purpose is to make fetch-edit-republish idempotent. Without it,
that cycle nests the server preamble.

### Lanes

The direct lane is taken when any of these hold: `CLAUDE_CODE_ENTRYPOINT` is `remote` or
`remote_cowork`, `CLAUDE_CODE_ARTIFACT_DIRECT_UPLOAD` is set, or `tengu_cobalt_plinth_direct` is
on, which it is by default. Otherwise the signed lane runs `deploy/init`, a presigned GCS `PUT`,
then `deploy/complete`. The multi-file lane (`deploy/prepare`, `upload`) sits behind
`tengu_cobalt_plinth_bracken`, default off.

### Concurrency

There is a real protocol here, worth using if you script alongside an open browser tab. A 409
returns `{conflict:true, live:"<version>"}` and the CLI's message is *"another session published a
newer version. Re-read it, merge your edits on top, then publish again."* Use `baseVersion` for
optimistic concurrency and `force` to clobber. They are mutually exclusive server side.

---

## Sharing

Publishing cannot set visibility. Going public is a second request, to a route the CLI never calls;
it belongs to the claude.ai share popover.

```http
PATCH /api/frame/perm/<slug>?org=<org uuid>
If-Match: <perm.version>

{"read": {"mode": "public", "users": []}, "shared": "<version>"}
```

```
2xx  {version}
409  {reason}                                        review gate or policy denial
412  {read, write, shared, version, writersEnabled}  ETag conflict, with server truth
```

The route is mounted on `api.anthropic.com` and accepts the CLI bearer token: a GET returns 405,
not 404. claude.ai itself is Cloudflare bot-gated for scripts and answers 403 "Just a moment", so
`api.anthropic.com` is the only host a script can use.

Read the permission record from `GET /api/frame/<slug>`. It is the only source of `perm.version`,
and that value is bumped by deploys as well as permission changes, so re-read it after every
publish or accept the 412.

### Read modes

| mode | label | meaning |
|---|---|---|
| `owner` | Only you | the default for every publish |
| `users` | Only people with access | per-account grants in `read.users` |
| `org` | Everyone in \<org\> | signed-in members of the organisation |
| `public` | Anyone with the link | no sign-in required |

`write.mode` is a strictly smaller set. There is no public write mode.

Check eligibility before you PATCH. The viewer's own predicate is
`assignableReadModes.includes("public")` when that array is present, otherwise
`externalSharingEnabled === true`, and it fails closed. A personal account sees
`["owner","public"]`, which means `users` and `org` are unavailable: **on a personal account the
only visibility above private is fully public.** Do not read `mayWiden` instead; that is a
different and more permissive predicate, and it fails open.

### `shared` is a version pin

This is the consequential finding, and it is measured rather than inferred. Public readability is
granted to exactly one reviewed version, not to the frame.

Direct experiment on a public artifact: note `live` and `shared`, redeploy with a marker string in
the body, then fetch both versions with no credentials.

```
before     live=…690-b99d   shared=…690-b99d
redeploy → 200, new version …539-faac, response carries read="public" shared="…690-b99d"
after      live=…539-faac   shared=…690-b99d          <- diverged

anon GET /_f/…690-b99d/   200, and does NOT contain the new marker
anon GET /_f/…539-faac/   403
```

So a redeploy strands every reader on the old content **and** leaves the new version unreadable to
them. The deploy response tells you this if you look: it echoes the unchanged `shared`.

Moving the pin is also a revocation. After re-pinning to the new version, the previously public
version returned 403. Exactly one version is public at any time.

The anonymous boot payload hands a visitor exactly one `ver` and omits `live`, `shared` and
`history`, so a stranger cannot discover that a newer version exists. The server refuses to unpin
while public (`unpin_refused`: *"Can't switch to Latest while shared publicly. Change who has
access first."*) and going public forces a pin.

**Redeploying a public artifact therefore strands viewers on the old version.** Move the pin with
`{"shared":"<new version>"}`.

Claude Code has a warning for exactly this case, *"viewers are pinned to an older version … they
will not see this update"*, which never fires. Its classifier drops `public` into a default branch
that asserts the opposite:

```js
function CWo(e,t){
  if(e===void 0||e===""||e==="owner") return {mode:"owner",isSharedLive:!1};
  if(e==="users"||e==="org")          return {mode:e,isSharedLive:(t??"")===""};
  return {mode:"unknown",isSharedLive:!0};        // "public" lands here
}
```

The pin warning requires `!isSharedLive`, so it is unreachable for public artifacts. On a personal
account the two branches handled correctly are themselves unreachable, so every shared artifact
takes the broken path and is described as *"(unrecognized share mode, treating as shared) …
viewers see updates immediately"*, which is backwards.

### The review gate

A fresh version is not immediately shareable. It passes an asynchronous scan first, and the PATCH
returns 409 until that clears. The reason vocabulary is closed, and four of the thirteen are
recoverable:

```
retry     missing_row  incomplete  generation_mismatch  upload_window_open
terminal  pin_required  missing_row_stale  unscannable  unvouchable_object
          unverifiable_age  nothing_served  unpin_refused
          connectors_declared  capability_forbids_public
```

The UI copy for the recoverable set is *"being reviewed for public sharing. Try again in a few
minutes."* **Unknown:** the actual duration. No bundle states it. Settle it by PATCHing immediately
after a publish and logging the reason and wall-clock until success.

### Verifying and revoking

Do not trust the PATCH. Ask the content origin without credentials, which is the CLI's own oracle
(`public_asset_forbidden`):

```bash
curl -so /dev/null -w '%{http_code}\n' https://<slug>.frame.claudeusercontent.com/_f/<version>/
```

Revoking is a PATCH back to `owner`, and it takes effect immediately. Measured: the content origin
returned 403 at t+0, t+5s, t+20s and t+60s after the revoke, with no cache window at all, despite
the served response carrying `s-maxage=300`. Anything a human already saved is of course gone
regardless.

Rotating the share key does not fully revoke. From the reset dialog: *"Links that include this
artifact's title will keep working. Rename the artifact to stop them. Older links that don't
include the title stop working. People who already have access keep it."*

---

## Limits

### Sizes, enforced client side

| bytes | symbol | measured on |
|---|---|---|
| 16,777,216 | `m6` | the composed document, before HTTP |
| 16,777,216 | `m6` | the source file on disk, checked twice |
| 16,777,216 | `m6` | per text file, multi-file lane |
| 15,728,640 | `gzo` | per binary file, lower so it survives base64 |
| 20,971,520 | `Gna` | per request, JSON-encoded, pre-checked only above `Gna/6` |
| 67,108,864 | `uTt` | all files in one version |
| 12,582,912 | `kgb` | inline budget: body versus a separate `upload` call |
| 33,554,432 | `2*m6` | axios `maxBodyLength` |
| 8,388,608 | `Svp` | mermaid injection span |
| 4,194,304 | `fvp` | highlight.js injection span |

Two traps. The 16 MiB applies to the *composed* document, and mermaid or highlight.js
auto-injection can silently add several megabytes to it. Separately, the Artifact tool schema caps
`files` at 64 while the pipeline allows 255; that gap is a prompt-level guardrail on the model, not
a platform limit, so a direct caller should reach 255.

Field limits: title 280 codepoints after normalisation, favicon 1 to 32 characters, description
1000, label 60, file path 512, root 1024. Manifest entries 256, being 255 files plus `index.html`.

### Server side, honestly

**Version history keeps exactly 20 versions.** Measured by pushing 51 versions at a single
artifact and reading `history` after each: it grew to 20 and then held at 20 for the remaining 31
publishes. No client contains this constant; the viewer infers pruning from data alone, rendering
"Older versions are no longer available". Whether an age component also exists is untested, but the
count is firm.

A daily publish cap exists somewhere. The string is `frame_daily_push_cap_reached`, observed on
`POST /api/frame/self/<uuid>`, and it appears zero times in the CLI bundle.

**It is not a per-artifact cap on publishing**, or if it is, the limit is above 51 per artifact per
day. 51 consecutive redeploys of one artifact all returned 200, at a sustained ~1.2 per second,
with no throttling and no rate-limit headers on any response. On the same day the account reached
roughly 113 publishes in total across all artifacts without refusal, so the account-wide cap is
above that if it governs this route at all.

Note the shape of that evidence. Ordinary usage is wide and shallow: on a representative day this
account published 59 versions across 58 artifacts, never more than 2 to any one of them. A
per-artifact cap would be invisible under that pattern, which is why it had to be tested directly
rather than inferred from history.

Artifact retention is a real organisation-admin setting with separate periods for private and
shared artifacts. No default is published anywhere.

There appears to be no cap on frames per account. No count constant, string, or error code exists
in any bundle, and the five recognised publish-denial reasons are all entitlement or policy rather
than quota. Retention looks like the growth bound instead.

**There is no rate-limit disclosure channel.** Frame responses carry no `anthropic-ratelimit-*`
headers and no `retry-after` on success. Unlike the Messages API, this control plane tells you
nothing about remaining budget. `request-id` is on every response and is your only support handle.

The CLI's 429 policy is one retry with no backoff and no jitter, and its failure mapper handles
422, 403 and 404 with no 429 branch at all, so hitting the daily cap surfaces as an uninterpreted
`deploy 429: {"error":"frame_daily_push_cap_reached"}`. Match that string explicitly and back off
for hours rather than the CLI's two seconds.

### Listing

`limit=200` is not a server maximum; 1000 works, and `0`, `-1` or `abc` return everything rather
than erroring. There is no pagination: `offset`, `cursor`, `page`, `after` and `before` are all
silently ignored.

`rel` is a real server-side filter the CLI never sends. `?rel=shared` returns zero rows while
`?rel=mine`, `?rel=bogus` and `?rel=` all return everything, and a bogus value returning everything
while `shared` returns nothing proves `shared` is specifically recognised. Push that filter server
side rather than filtering locally as the CLI does.

The CLI ships two independent list implementations that do not know about each other: the TUI
gallery with a 14-field schema, and the Artifact tool's `action:"list"` with 5. The gallery drops
`audience`, which is why **Claude Code can never show you which of your artifacts are public**.

The published documentation states exactly one number, the 16 MiB rendered size. No daily cap, no
rate limit, no count, no retention. It also still says "Single page", so the entire multi-file
manifest path is undocumented.

---

## Compression

Transport compression is unavailable and would not help. No `Content-Encoding` appears anywhere in
the frame path; the only gzip-emitting code in 24 MB is the OpenTelemetry exporter. The size check
runs on `Buffer.byteLength(composed,"utf8")` before HTTP exists, so a server enforcing the same
rule decodes first and measures the same number. The signed lane cannot be compressed either,
because the GCS signed URL's signature covers the canonical headers.

Served compression is automatic, and gzip only. Measured on a public frame: `gzip` yields 7,037
bytes against 16,651 for `identity`, a 2.37x saving, while `br` and `zstd` are simply not offered.
The server also injects roughly 12 KB of runtime preamble ahead of your document at serve time,
which is not charged against your 16 MiB.

Content-level compression is the only lever you control, and the CSP is permissive enough to allow
it: `script-src 'self' 'unsafe-inline' 'unsafe-eval' blob:`, `worker-src 'self' blob:`, WASM
allowed. `DecompressionStream` issues no request and evaluates no code, so no directive applies.

Effective multipliers, gzip -9 then base64, against the 16 MiB budget:

| data | gzip | effective | budget becomes |
|---|---|---|---|
| JSON records | 13.85x | 10.39x | ~166 MiB |
| minified JS | 3.54x | 2.65x | ~42 MiB |
| prose | 2.86x | 2.14x | ~34 MiB |
| numeric CSV | 2.18x | 1.64x | ~26 MiB |
| random bytes | 1.00x | 0.75x | 12 MiB, a net loss |

Break-even is a gzip ratio of 4/3. Clear win for JSON, logs, CSV and source; clear loss for
anything already entropy-coded such as PNG, JPEG, WebP, MP4 or WOFF2. Base64 costs quota but not
download bytes: 335,192 bytes of base64 re-gzips on the wire to 224,990, fewer than the bare gzip
would have been, because base64's alphabet is itself compressible.

One CSP detail will break a first attempt. `connect-src 'self'` includes neither `blob:` nor
`data:`, so `fetch(URL.createObjectURL(blob))` is blocked. Feed the stream directly:

```js
const bytes = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
const text  = await new Response(
  new Blob([bytes]).stream().pipeThrough(new DecompressionStream('gzip'))
).text();
```

Put the base64 in a `<template>`. Its alphabet contains no `<` or `&`, so it survives HTML parsing
with zero escaping overhead, unlike a JS string literal.

Alternatives, briefly: base93 raises packing from 75% to about 82%, which is marginal. Non-ASCII is
strictly worse, since U+0080 to U+07FF costs two UTF-8 bytes for 11 bits against base64's 6 bits
per byte. A brotli or zstd WASM decoder beats gzip by 15 to 25% on text but costs 100 to 300 KB
inlined, so it only pays above roughly 2 MB of payload. `deflate-raw` saves 26 bytes over `gzip`.

If the multi-file gate is on for your account it beats all of this: 64 MiB, no decode complexity,
and supporting files sit under the injected `<base href="/_f/<ver>/">` so `fetch('data.bin')` is
same-origin and passes `connect-src 'self'`.

Worth noting that the CLI's own 3.3 MB mermaid and 1 MB highlight.js payloads are stored
uncompressed and injected as raw inline text. Anthropic's answer to size here is minification.

---

## Capabilities

`GET /api/frame/contract/latest` returns `{"version":"0.1.18","capabilities":["downloads","mcp"]}`.
Behind it sits a full read-only subsystem: `/contract/<semver>`, `/<semver>/prompt` and
`/<semver>/<cap>.d.ts`. Walking every version back to `0.1.0` shows `mcp` alone through `0.1.6`,
with `downloads` added at `0.1.7`.

### Four capabilities exist that the contract does not advertise

The advertised list is `["downloads","mcp"]`, but `<version>/<name>.d.ts` returns real type
definitions for **`self`, `db`, `user` and `permissions`** as well. These are not a catch-all:
`network.d.ts` and `storage.d.ts` return 404.

| name | advertised | `.d.ts` |
|---|---|---|
| `downloads` | yes | 3,564 bytes |
| `mcp` | yes | 26,931 bytes |
| `self` | no | 6,971 bytes |
| `db` | no | 14,746 bytes |
| `user` | no | 3,593 bytes |
| `permissions` | no | 4,091 bytes |
| `network`, `storage` | no | 404 |

`self` is the interesting one, because it is a live multi-viewer write channel. Verbatim from its
own documentation:

`window.claude.self` publishes a new version of the page it runs in. Quoting its documentation:

> The page hands the shell a complete replacement `index.html`; the shell publishes it as a new
> immutable version of the same artifact with the viewer's own authority, and every open view
> live-reloads to it.

`publish(html)` is compare-and-set against the version the calling view is running. Its error
vocabulary is instructive: `conflict` (someone published first, and the shell is already reloading
every view to the winner), `not_writer` (the viewer can read but not write), `not_declared`,
`too_large`, `invalid_content`, `rate_limited` ("slow down and batch"), `consent_required`, plus
the permanent lifecycle codes `not_granted`, `capability_disabled`, `capability_removed` and
`transform_error`.

Two consequences worth drawing out. This is the platform's own supported mechanism for a
live-updating shared page, so a real-time channel over a single artifact does not require any
sandbox trickery. But it needs a browser view open on each end, since the capability lives in the
rendered page's runtime rather than in the API, and the writers must genuinely have write access.
A probe of a rendered artifact found `self.*` rejecting with `[not_granted]`, which the type
definitions explain: the capability must be declared by the artifact and granted to the view.

**Declaring `mcp` permanently forecloses public sharing.** The contract's own prompt text says it
is a viewer-consented grant and a declaring page cannot be shared publicly, and the viewer enforces
this by mapping both `connectors_declared` and `capability_forbids_public` to *"This artifact uses
connectors, so it can't be shared publicly."* The only way back is republishing without it.

Omitting `contract` on a redeploy is not a no-op. The CLI reads the artifact's stored capability
pin and, if that read fails, refuses to publish at all: *"a republish preserves the stored pin, so
this publish cannot proceed without it."* A client that simply re-POSTs `content` silently retains
whatever capabilities were declared three publishes ago. Clearing them needs `capabilities: {}`
together with the current contract version.

---

## Endpoints

| route | verb | notes |
|---|---|---|
| `deploy/direct` | POST | the default publish |
| `deploy/{init,prepare,complete}` | POST | signed and multi-file lanes |
| `upload` | POST | multi-file sidecars |
| `frames[?limit=&rel=]` | GET | list; `rel` is server side, no pagination |
| `<slug>[?via=model_read]` | GET | the boot record: `perm`, `live`, `history`, tokens |
| `<slug>` | DELETE | 204 |
| `read/<slug>` | GET | stored declaration and content read-back |
| `perm/<slug>?org=` | PATCH | visibility. No GET, returns 405 |
| `versions/<uuid>[?org=]` | GET | owner only: `{live, shared, history, versions, last_edit}` |
| `share-key/<slug>/rotate` | POST | "Reset link", does not kill vanity links |
| `duplicate/<slug>` | POST | fork |
| `retitle/<slug>` | POST | |
| `report/<slug>` | POST | 13 categories, 202 accepted, anonymous-capable |
| `comments/<slug>[/<thread>[/resolve]]` | POST | |
| `access-request{,s}/…` | POST | |
| `self/<uuid>` | POST | in-page self-update; source of `frame_daily_push_cap_reached` |
| `{sync,control/<uuid>,track,telemetry}` | POST | live layer and telemetry |
| `contract/{latest,<semver>,…}` | GET | read only |

---

## Traps

The raw content origin serves your page with no authentication and no chrome: no byline, no
"user-generated and unverified" disclaimer, no Report button. Both URLs carry `noindex`, at the
HTML level for the viewer and as `x-robots-tag` on the content origin, so public means link-only
rather than discoverable. Neither product has a public gallery.

Any signed-out visitor can file an abuse report. Thirteen categories, of which four (copyright,
trademark, private information, court order) divert to a legal intake form. A takedown sets
`softDeleted` and the owner then sees *"unpublished by Anthropic and visible only to you."* There
is no appeal affordance anywhere in the viewer bundle.

Slug bookkeeping is entirely yours. The CLI's path-to-slug and slug-to-state maps are plain
in-memory `Map`s in a module closure, with nothing on disk. Persist the source path, slug, live
version, `perm.version`, contract and capabilities yourself.

The tokens in a frame record are credentials, not metadata. `assetToken` is a structured bearer
capability lasting about an hour, carried as `?__frame_t=` on the content iframe, and the viewer
reads its own account UUID out of its third dot-separated segment. There are also `wsToken`,
`syncToken`, `consentToken`, `share_key` and `subscriptionToken`. Do not log them and do not place
them in artifact content.

View analytics are wired but not populated. `view_count`, `unique_view_count` and `needs_pin` are
parsed and rendered client side yet absent from every live row. `thumbsEnabled` is false, so no
thumbnail is captured by 2.1.223 despite `deploy/init` being wired for `thumbType`. Stars are
unshipped: the icons exist with zero call sites.

The owner's email renders as the byline only when the viewer is the owner. **Unknown:** whether the
server withholds `author.email` from a public viewer or only the client does. The public boot
narrowing is a client-side field whitelist, which is defence in depth rather than the control. The
observed unauthenticated response returned only `kind`, `mode`, `ver`, `title`, `favicon`,
`description`, `hasThumb` and `reportEnabled`, which is reassuring but was measured on one account.

---

## Chats are not this API

There is no scripted equivalent for conversations, and the CLI bearer token is refused by that
surface. The CLI bundle contains zero occurrences of `chat_conversations`, `conversation_uuid` or
`claude.ai/share`. Conversations are cookie-authenticated on claude.ai, which is Cloudflare
bot-gated for scripts. Sharing a conversation deploys nothing; it flips visibility on something
that already exists server side, producing a frozen copy at `claude.ai/share/<id>`.

The only documented Anthropic API touching claude.ai chats is the Compliance API: read and
hard-delete only, no share verb, Enterprise only, and it requires a Compliance Access Key that
explicitly refuses Admin API keys.

---

## Re-deriving after a CLI upgrade

The binary is Bun-compiled with its JS bundle embedded as a contiguous printable region of roughly
24 MB. In 2.1.223 it sits near byte offset 239.5M. Note that `/api/frame/deploy/direct` also occurs
around 113M in a different region, which yields a useless 16 KB slice, so take the last occurrence:

```python
import os
data = open(os.path.expanduser("~/.local/bin/claude"), "rb").read()
target = data.rindex(b"/api/frame/deploy/direct")

printable = set(range(32, 127)) | {9, 10, 13}
def scan(start, step):
    i, bad, last = start, 0, start
    while 0 <= i < len(data):
        if data[i] in printable or data[i] >= 0xC2:
            bad, last = 0, i
        else:
            bad += 1
            if bad > 200:
                break
        i += step
    return last

open("bundle.js", "wb").write(data[scan(target, -1):scan(target, 1) + 1])
```

The viewer bundles are public static assets needing no auth:

```bash
curl -s https://claude.ai/code/artifact/<any-slug> | grep -oE 'https://assets-proxy[^"]+\.js'
```

`frame-shell-chrome-*.js` is the one that matters: share dialog, permissions, versions.

Symbol names rotate every release. For 2.1.223:

| 2.1.222 | 2.1.223 | |
|---|---|---|
| `QSp` | `oCp` | direct-lane publish |
| `YSp`, `vGo` | `mzo`, `tCp` | publish orchestrator |
| `cTp` | `hCp` | `composeArtifactPage` |
| `Z9` | `p6` | `X-Frame-*` header builder |
| `Fta` | `roa` | identity fields |
| `zCe` | `y0e` | viewer URL template |
| `DV` | `pve` | auth-header builder |
| `NKg` | `we_` | host registry |
| `t6` | `m6` | `MAX_ARTIFACT_BYTES` |
| | `ugb` | the CSS reset |
| | `pzo`, `noa` | pre-compose sanitiser |
| | `$Ar`, `MVo`, `CWo` | boot read, share status, read-mode mapper |
| | `PC`, `Ron` | URL parser, UUID regex |
| | `zvo`, `$7` | title pipeline |

Grep with byte-offset context windows rather than `grep -n`. The file is minified onto enormous
lines and a single match will print megabytes.

---

## What is verified, and what is not

Confirmed against the live API: publish, redeploy in place, delete, listing including `rel`
filtering and limit behaviour, the frame record both authenticated and anonymous, the contract
endpoints, `versions/<uuid>`, the per-version 200 and 403 pattern on the content origin, served
compression negotiation, and the 405 on `GET /api/frame/perm/<slug>` that proves the route is
mounted on `api.anthropic.com`.

Also confirmed live, 2026-08-06, against a throwaway artifact:

- **`PATCH /api/frame/perm/<slug>` accepts the CLI bearer token on `api.anthropic.com`.** It works
  with `?org=<uuid>` resolved from `~/.claude.json`; the no-org fallback never had to fire.
- **A redeploy does not advance `shared`.** Readers keep the old version and cannot read the new
  one at all. The deploy response echoes the stale `shared`.
- **Re-pinning revokes the previous version.** Exactly one version is public at a time.
- **Revoking is immediate**, with no observable cache window.
- The review gate did not fire on either flip, including on a version about a minute old, so the
  `409` retry path remains defensive and unexercised. Its duration is still unknown.

Read in the bundles but never exercised: the signed and multi-file lanes, `share-key/rotate`,
`duplicate`, `retitle`, `report`, `comments`, `self` at runtime, `sync`, `control`, and the
`capabilities`, `force` and `baseVersion` fields.

Open questions, each stated as the experiment that settles it. All require a mutating request.

| question | experiment |
|---|---|
| Where is the account-wide daily publish cap? | keep publishing past ~113/day and watch for the refusal. Destroys the day's quota |
| How long is the review window, and what triggers it? | flip to public immediately after publishing a large or complex page, log the 409 reason and time to success |
| Can `self` be declared, given it is not in the advertised list? | publish with `contract: "0.1.18"` and `capabilities: {self: {}}`, then open the page and call it |
| Is `assignableReadModes` enforced or advisory? | `PATCH {"read":{"mode":"org"}}` on a personal-account throwaway |
| Where is the server's own size threshold? | POST exactly 16,777,216 then 16,777,217 bytes and read the 400 body |
| Does version retention also have an age component? | leave an artifact with 20 versions untouched for days, then re-read `versions/<uuid>` |
| Does DELETE purge the content origin? | delete a throwaway, re-GET its raw URL |
| Is the multi-file gate on for this account? | one publish with a two-entry `files` map |
| Does `DecompressionStream` run in the shipping viewer? | publish a two-line try/catch artifact |
