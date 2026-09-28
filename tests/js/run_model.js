// Evaluates [{fn, args}] against Model.js (path in argv[2]) and prints the
// results as JSON, for tests/test_parity.py. Callback arguments are encoded:
// {"$proxyNames": {id: name}} becomes a lookup function.
const fs = require("fs"), vm = require("vm")
const ctx = {}
vm.createContext(ctx)
vm.runInContext(fs.readFileSync(process.argv[2], "utf8"), ctx)
const calls = JSON.parse(fs.readFileSync(0, "utf8"))
const out = calls.map(c => {
  const args = c.args.map(a => a && typeof a === "object" && a.$proxyNames ? (id => a.$proxyNames[id] || "?") : a)
  try { const r = ctx[c.fn].apply(null, args); return r === undefined ? null : r }
  catch (e) { return { $error: String(e) } }
})
process.stdout.write(JSON.stringify(out))
