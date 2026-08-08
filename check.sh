#!/usr/bin/env bash
# Everything that can be verified without a network, a browser or credentials.
#
#   ./check.sh
#
# Run this before publishing an artifact or pushing. Every failure it reports is
# one that actually happened during development, which is why each check exists.
set -uo pipefail
cd "$(dirname "$0")"

PASS=0; FAIL=0
ok(){ printf '  \033[32mok\033[0m   %s\n' "$1"; PASS=$((PASS+1)); }
bad(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; [ -n "${2:-}" ] && printf '       %s\n' "$2"; FAIL=$((FAIL+1)); }
have(){ command -v "$1" >/dev/null 2>&1; }

PY=.venv/bin/python
[ -x "$PY" ] || PY=python3

echo "python"
for f in clawdvert/*.py tests/*.py; do
  if err=$("$PY" -m py_compile "$f" 2>&1); then ok "$f parses"; else bad "$f" "$err"; fi
done
if err=$("$PY" tests/test_mailbox.py 2>&1); then
  ok "offline test suite ($(echo "$err" | grep -c '  pass') cases)"
else
  bad "offline test suite" "$(echo "$err" | tail -3)"
fi

echo
echo "html clients"
for f in realm/*.html; do
  [ -e "$f" ] || continue

  # A literal closing script tag anywhere in the file, including inside a JS
  # string or a comment, ends the block early. The HTML parser scans raw text
  # and knows nothing about JavaScript. This has bitten twice.
  closers=$(grep -c '</script>' "$f")
  opens=$(grep -c '<script' "$f")
  if [ "$closers" -eq "$opens" ]; then
    ok "$(basename "$f") script tags balance ($opens)"
  else
    bad "$(basename "$f") script tags" "$opens open, $closers close: a literal </script> is hiding in a string or comment"
  fi

  # Extract the largest script block and parse it. Catches the unbalanced brace
  # class of error that a careless edit introduces.
  if have node; then
    "$PY" - "$f" <<'EOF' >/tmp/_check.js 2>/dev/null
import re, sys, pathlib
h = pathlib.Path(sys.argv[1]).read_text()
blocks = re.findall(r'<script[^>]*>(.*?)</script>', h, re.S)
sys.stdout.write(max(blocks, key=len) if blocks else "")
EOF
    if [ -s /tmp/_check.js ]; then
      if err=$(node --check /tmp/_check.js 2>&1); then
        ok "$(basename "$f") javascript parses"
      else
        bad "$(basename "$f") javascript" "$(echo "$err" | head -3)"
      fi
    fi
  fi

  # Function declarations hoist; const and let do not. A top-level call placed
  # above a later const runs while that const is still in its temporal dead
  # zone, and if anything it reaches touches that const it throws, aborting the
  # rest of startup with no visible error. The previous version of this check
  # compared where a name was *written* against where it was declared, which is
  # why it passed while DIRECT_ONLY was crashing startup: the read sat four
  # lines below its own declaration, but the call chain began 1900 lines above.
  #
  # The invariant instead: no statement-position call at IIFE top level may
  # appear before the last top-level declaration. Bootstrap from the bottom.
  tdz=$("$PY" - "$f" <<'EOF'
import re, sys, pathlib

# Built with chr(96) so no backtick appears literally: this python is embedded
# inside a bash $( ) substitution, where a stray backtick opens a subshell.
QUOTES = ('"', "'", chr(96))

def strip_noise(js):
    """Blank strings, template literals and comments so brace counting sees
    only structure. Newlines are preserved so line numbers stay true."""
    out, i, n = [], 0, len(js)
    while i < n:
        c = js[i]
        if c == '/' and i+1 < n and js[i+1] == '/':
            j = js.find('\n', i); j = n if j < 0 else j
            out.append(' ' * (j-i)); i = j
        elif c == '/' and i+1 < n and js[i+1] == '*':
            j = js.find('*/', i+2); j = n if j < 0 else j+2
            out.append(''.join(ch if ch == '\n' else ' ' for ch in js[i:j])); i = j
        elif c in QUOTES:
            q, j = c, i+1
            while j < n:
                if js[j] == '\\': j += 2; continue
                if js[j] == q: j += 1; break
                j += 1
            out.append(''.join(ch if ch == '\n' else ' ' for ch in js[i:j])); i = j
        else:
            out.append(c); i += 1
    return ''.join(out)

KEYWORDS = {"if","for","while","switch","catch","function","return","typeof","await","new",
            "delete","void","do","else","try","throw","constructor","get","set","static"}

src = pathlib.Path(sys.argv[1]).read_text()
m = re.search(r'<script[^>]*>(.*?)</script>', src, re.S)
js = m.group(1) if m else ""
base = src[:m.start(1)].count("\n") + 1 if m else 1
decls, calls, depth = [], [], 0
for lineno, line in enumerate(strip_noise(js).split("\n")):
    stripped = line.strip()
    if depth == 1:                      # depth 1 is the IIFE body itself
        d = re.match(r'(?:const|let)\s+([A-Za-z_$][\w$]*)\s*=', stripped)
        if d: decls.append((lineno, d.group(1)))
        c = re.match(r'([a-zA-Z_$][\w$]*)\s*\(', stripped)
        if c and c.group(1) not in KEYWORDS: calls.append((lineno, c.group(1)))
    depth += line.count("{") - line.count("}")
bad = []
if decls:
    last_line, last_name = max(decls)
    bad = [f"{name}() at line {base+ln} runs before {last_name} exists (line {base+last_line})"
           for ln, name in calls if ln < last_line]
print("; ".join(bad[:3]))
EOF
)
  if [ -z "$tdz" ]; then ok "$(basename "$f") bootstraps after every declaration"
  else bad "$(basename "$f") temporal dead zone risk" "$tdz"; fi

  # Every getElementById the script reaches for should exist in the markup.
  # A renamed id fails silently at runtime as a null dereference.
  missing=$("$PY" - "$f" <<'EOF'
import re, sys, pathlib
h = pathlib.Path(sys.argv[1]).read_text()
ids = set(re.findall(r'\bid="([^"]+)"', h))
used = set(re.findall(r'\$\("([^"]+)"\)', h)) | set(re.findall(r'getElementById\("([^"]+)"\)', h))
gone = sorted(used - ids)
print(" ".join(gone[:8]) if gone else "")
EOF
)
  if [ -z "$missing" ]; then ok "$(basename "$f") every referenced id exists"
  else bad "$(basename "$f") missing ids" "$missing"; fi
done

echo
echo "prose"
for f in README.md docs/*.md; do
  [ -e "$f" ] || continue
  n=$(grep -c '—' "$f")
  [ "$n" -eq 0 ] && ok "$(basename "$f") no em dashes" || bad "$(basename "$f") $n em dash(es)"
done

echo
echo "hygiene"
if git ls-files | grep -qE 'relay\.json|\.relay-state|\.pem$|\.env$'; then
  bad "a credential file is tracked" "$(git ls-files | grep -E 'relay\.json|\.relay-state|\.pem$|\.env$')"
else ok "no credential files tracked"; fi

if [ -n "$(git status --porcelain)" ]; then
  printf '  \033[33mnote\033[0m uncommitted changes:\n'
  git status --short | sed 's/^/       /'
else ok "working tree clean"; fi

echo
printf '%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
