// Reads the widget makes itself (LIST, LOG, RULES) and other reads are noise
// in the popup; the full log is one click away.
const quiet = { LIST: true, LOG: true, VERSION: true, RULES: true }
const shells = { "agent-keychain": true, bash: true, zsh: true, sh: true, dash: true, fish: true, nu: true, env: true }
const terminals = { ghostty: true, alacritty: true, kitty: true, foot: true, wezterm: true, "wezterm-gui": true, konsole: true }

function parseJson(raw, fallback) {
  try {
    var parsed = JSON.parse(raw)
    return Array.isArray(parsed) ? parsed : fallback
  } catch (error) {
    return fallback
  }
}

// "agent-keychain <- bash <- claude <- bash" -> "claude"
function agentName(caller) {
  var chain = String(caller || "").split(" <- ")
  for (var i = 0; i < chain.length; i++) {
    if (chain[i] && !shells[chain[i]]) return terminals[chain[i]] ? "terminal" : chain[i]
  }
  return chain[0] || "?"
}

function outcomeKind(outcome) {
  if (outcome === "denied" || outcome === "denied-by-rule" || outcome === "refused" || outcome === "throttled") return "denied"
  if (outcome === "error" || outcome === "malformed" || outcome === "missing" || outcome === "busy") return "error"
  return "ok"
}

function recent(entries, limit) {
  var out = []
  for (var i = entries.length - 1; i >= 0 && out.length < limit; i--) {
    var e = entries[i]
    if (!e || quiet[e.request]) continue
    out.push({
      time: e.time,
      request: e.request,
      name: e.name || "",
      agent: agentName(e.caller),
      caller: e.caller || "",
      outcome: e.outcome || "",
      kind: outcomeKind(e.outcome)
    })
  }
  return out
}

function ago(iso, nowMs) {
  var t = Date.parse(iso)
  if (isNaN(t)) return ""
  var s = Math.max(0, Math.round((nowMs - t) / 1000))
  if (s < 60) return s + "s"
  if (s < 3600) return Math.floor(s / 60) + "m"
  if (s < 86400) return Math.floor(s / 3600) + "h"
  return Math.floor(s / 86400) + "d"
}

function ruleLabel(rule) {
  return rule.effect + " " + rule.agent + " " + rule.secret
}
