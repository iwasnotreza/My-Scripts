-- OPTIONAL runtime dumper for H4x loader analysis.
-- WARNING: this DOES execute the remote loader. Use only on a throwaway account
-- or in a controlled analysis environment. It is not needed for the static
-- Python decoder; use decode_loader.py first if possible.
--
-- What it does:
--   1) downloads https://h4xscripts.xyz/loader and saves raw_loader.lua
--   2) hooks loadstring/load so every Lua chunk passed to them is dumped
--   3) executes the loader and reports errors
--
-- Dumped files are named h4x_stage_001.lua, h4x_stage_002.lua, ...

local URL = "https://h4xscripts.xyz/loader"

local function get_writefile()
    if writefile then return writefile end
    if syn and syn.write_file then return syn.write_file end
    if filesystem and filesystem.write then return filesystem.write end
    return nil
end

local wf = get_writefile()
if not wf then
    warn("[h4x-dump] writefile is not available; cannot dump stages")
    return
end

local old_loadstring = loadstring or load
local old_load = load or loadstring
if not old_loadstring then
    warn("[h4x-dump] no loadstring/load available")
    return
end

local count = 0
local function dump_chunk(src, label)
    if type(src) ~= "string" then return end
    if #src < 64 then return end
    count = count + 1
    local name = ("h4x_stage_%03d.lua"):format(count)
    pcall(wf, name, src)
    print(("[h4x-dump] %s  %d bytes  %s"):format(name, #src, tostring(label or "")))
end

-- Hook loadstring
loadstring = function(src, chunkname)
    dump_chunk(src, chunkname)
    return old_loadstring(src, chunkname)
end

-- Hook load (Lua 5.2+/Luau style). Preserve function-reader behavior.
load = function(src, chunkname, mode, env)
    if type(src) == "string" then
        dump_chunk(src, chunkname)
    end
    return old_load(src, chunkname, mode, env)
end

print("[h4x-dump] downloading raw loader...")
local ok, body = pcall(function()
    return game:HttpGet(URL)
end)
if not ok or type(body) ~= "string" then
    warn("[h4x-dump] HttpGet failed: " .. tostring(body))
    return
end

pcall(wf, "raw_loader.lua", body)
print(("[h4x-dump] raw_loader.lua saved (%d bytes)"):format(#body))

local fn, err = old_loadstring(body, "@h4x_loader")
if not fn then
    warn("[h4x-dump] compile failed: " .. tostring(err))
    return
end

print("[h4x-dump] executing loader (hooks active)...")
local ran, result = pcall(fn)
if not ran then
    warn("[h4x-dump] runtime error: " .. tostring(result))
else
    print("[h4x-dump] loader returned: " .. tostring(result))
end

print(("[h4x-dump] done; dumped %d chunk(s)"):format(count))
