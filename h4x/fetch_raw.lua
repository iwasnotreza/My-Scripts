-- Executor helper: download the raw loader body WITHOUT executing it.
-- Run this in a Roblox executor, then copy the saved file back to the repo as:
--   h4x/raw_loader.lua
--
-- It only performs an HTTP GET and writes a file. It does not call loadstring.

local URL = "https://h4xscripts.xyz/loader"
local OUT = "raw_loader.lua"

local function get_writefile()
    if writefile then return writefile end
    if syn and syn.write_file then return syn.write_file end
    if filesystem and filesystem.write then return filesystem.write end
    return nil
end

local wf = get_writefile()
if not wf then
    warn("[h4x] writefile is not available in this executor")
    return
end

local ok, body = pcall(function()
    return game:HttpGet(URL)
end)

if not ok then
    warn("[h4x] HttpGet failed: " .. tostring(body))
    return
end

if type(body) ~= "string" or #body == 0 then
    warn("[h4x] empty or invalid response")
    return
end

wf(OUT, body)
print(("[h4x] saved %d bytes to %s"):format(#body, OUT))
