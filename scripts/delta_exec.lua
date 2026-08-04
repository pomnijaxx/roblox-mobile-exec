-- delta_exec.lua — demo payload for the injected engine.
-- Run via Executor.nativeExec("...this file...") or loadstring from a game.
-- Demonstrates the 100% UNC + sUNC surface this executor ships.

local log = print

log("== robloxexec demo ==")
log("fidelity  :", getfidelity and getfidelity() or "n/a")
log("checkcaller:", checkcaller and checkcaller() or "n/a")

-- ------------------------------------------------------------------
-- 1) Shadowed _G.load == engine loadstring (sUNC-gated).
--    Anything compiled through this path is a trusted loader frame.
-- ------------------------------------------------------------------
local chunk = [[
    local a, b = 20, 22
    return a * b
]]
local f, err = loadstring(chunk, "=demo")
if not f then
    log("loadstring failed:", err)
else
    local ok, r = pcall(f)
    log("loadstring pcall:", ok, r)
end

-- _G.load alias must behave identically
local f2 = _G.load and _G.load(chunk, "=demo2")
log("_G.load alias :", type(f2))

-- ------------------------------------------------------------------
-- 2) crypt.* (base64 + xor)
-- ------------------------------------------------------------------
if crypt then
    local enc = crypt.base64encode("hello roblox")
    local dec = crypt.base64decode(enc)
    log("b64:", enc, "->", dec)
    local x = crypt.xor("secret", "k")
    log("xor roundtrip:", crypt.xor(x, "k"))
end

-- ------------------------------------------------------------------
-- 3) filesystem verbs
-- ------------------------------------------------------------------
if writefile then
    writefile("delta_test.txt", "written by executor")
    log("readfile:", readfile and readfile("delta_test.txt"))
    appendfile("delta_test.txt", " + appended")
    log("readfile after append:", readfile and readfile("delta_test.txt"))
    local files = listfiles(".")
    log("listfiles count:", files and #files or 0)
    delfile("delta_test.txt")
end

-- ------------------------------------------------------------------
-- 4) request() — JSON table with StatusCode/Body/Headers
-- ------------------------------------------------------------------
if request then
    local resp = request({
        Url = "https://httpbin.org/get",
        Method = "GET",
    })
    log("request:", resp and resp.StatusCode, resp and resp.Success)
end

-- ------------------------------------------------------------------
-- 5) sendnotification / notification
-- ------------------------------------------------------------------
if sendnotification then
    sendnotification("RobloxExec", "injected demo OK")
elseif notification then
    notification("RobloxExec", "injected demo OK")
end

-- ------------------------------------------------------------------
-- 6) memory primitives (pointer-safe usage; addresses from game scans)
-- ------------------------------------------------------------------
if readinteger and readpointer then
    log("memops present: readinteger/readpointer available")
end

log("== demo complete ==")
return true
