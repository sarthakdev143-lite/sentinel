# =============================================================================
# config.example.nim - single engagement-config surface
# =============================================================================
# Copy to config.nim (gitignored), fill in, and build. Every value here
# is ALSO overridable at runtime via env vars where noted, so baking is
# optional for the Telegram transport.
#
#   cp config.example.nim config.nim
#   # edit config.nim
#
# Build scripts fail loudly if a referenced config.nim is missing.

const
  # --- Shared engagement secret (agent + server MUST match) ---
  # Runtime override: none (baked). Rotate per engagement.
  CFG_AGENT_SECRET* = "sentinel-engagement-q4-2026-echo-tango-whiskey"

  # --- Web dashboard basic auth (c2_server only) ---
  CFG_WEB_USER* = "operator"
  CFG_WEB_PASS* = "S3nt1n3l-C2-D3v-Only-CHANGEME"

  # --- Telegram (sentinel -Tg / telegram agent) ---
  # Runtime overrides: TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID env vars.
  CFG_TG_BOT_TOKEN* = ""
  CFG_TG_CHAT_ID*   = ""

  # --- WebSocket C2 URLs (WS / both transports) ---
  # Runtime override: SENTINEL_C2_URLS env or --c2= CLI flags.
  CFG_C2_URLS* = @["ws://127.0.0.1:8443"]

  # --- TLS pinning (WS only): full PEM text, empty disables ---
  CFG_PINNED_CERT_PEM* = ""

  # --- Log filename prefix (both sides must match) ---
  CFG_BUILD_PREFIX* = "X7K"
