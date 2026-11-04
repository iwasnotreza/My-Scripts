-- Safe helper: only downloads the raw loader body. Does NOT execute it.
-- Run this in your executor, then send/attach the generated raw_loader.lua file.

local url = "https://h4xscripts.xyz/loader"
local ok, body = pcall(function()
    if syn and syn.request then
        return syn.request({Url = url, Method = "GET"}).Body
    elseif request then
        return request({Url = url, Method = "GET"}).Body
    elseif http_request then
        return http_request({Url = url, Method = "GET"}).Body
    elseif game and game.HttpGet then
        return game:HttpGet(url)
    else
        error("No HTTP request function found in this executor")
    end
end)

if not ok then
    warn("fetch_raw failed: " .. tostring(body))
    return
end

local filename = "raw_loader.lua"
if writefile then
    writefile(filename, body)
    print("Saved " .. filename .. " (" .. #body .. " bytes). Send this file back.")
else
    warn("writefile is not available; copy the body manually.")
end
