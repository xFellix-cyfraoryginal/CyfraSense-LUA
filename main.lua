local HttpService = game:GetService("HttpService")
local Players = game:GetService("Players")
local env = type(getgenv) == "function" and getgenv() or _G
local url = "https://cyfraoryginal.xyz"
local folder = "CyfraSense"
local files = {key = folder .. "/license.key", device = folder .. "/device.id", token = folder .. "/device.token"}
local requester = env.request or env.http_request or (type(env.syn) == "table" and env.syn.request) or (type(env.http) == "table" and env.http.request) or rawget(_G, "request")
assert(type(requester) == "function", "[CS] HTTP request is unavailable")
assert(type(loadstring) == "function", "[CS] loadstring is unavailable")
local function read(path)
    if type(isfile) ~= "function" or type(readfile) ~= "function" then return "" end
    local ok, exists = pcall(isfile, path)
    if not ok or not exists then return "" end
    local readOk, result = pcall(readfile, path)
    return readOk and type(result) == "string" and result or ""
end
local function save(path, value)
    if type(writefile) ~= "function" then return false end
    if type(makefolder) == "function" and type(isfolder) == "function" then
        pcall(function() if not isfolder(folder) then makefolder(folder) end end)
    end
    return pcall(writefile, path, value)
end
local function hex64()
    return (HttpService:GenerateGUID(false) .. HttpService:GenerateGUID(false)):gsub("-", ""):lower()
end
local function deviceId()
    local id = read(files.device):lower():gsub("%s", "")
    if #id == 64 and id:match("^[a-f0-9]+$") then return id end
    id = hex64()
    assert(save(files.device, id), "[CS] Cannot save device ID")
    return id
end
local function executorId()
    local fn = env.identifyexecutor or env.getexecutorname or rawget(_G, "identifyexecutor")
    if type(fn) ~= "function" then return "unknown" end
    local ok, name = pcall(fn)
    return ok and tostring(name):sub(1, 80) or "unknown"
end
local function environment() return env end
local function cleanHwidValue(value)
    if value == nil then
        return ""
    end
    value = tostring(value):gsub("[%c]", ""):gsub("^%s+", ""):gsub("%s+$", "")
    if #value < 8 or #value > 256 then
        return ""
    end
    return value
end
local function hwidProviders()
    local env = environment()
    return {
        {name = "gethwid", fn = env.gethwid, kind = "hwid"},
        {name = "get_hwid", fn = env.get_hwid, kind = "hwid"},
        {name = "getfingerprint", fn = env.getfingerprint, kind = "fingerprint"},
        {name = "_G.gethwid", fn = rawget(_G, "gethwid"), kind = "hwid"},
        {name = "_G.get_hwid", fn = rawget(_G, "get_hwid"), kind = "hwid"},
        {name = "_G.getfingerprint", fn = rawget(_G, "getfingerprint"), kind = "fingerprint"}
    }
end
local function sampleHwidProvider(fn)
    local first = ""
    local seenValid = false
    for _ = 1, 3 do
        local ok, value = pcall(fn)
        if ok then
            value = cleanHwidValue(value)
            if value ~= "" then
                if seenValid and value ~= first then
                    return "", false
                end
                first = value
                seenValid = true
            end
        end
    end
    return first, true
end
local function obviousSpoofValue(value)
    value = cleanHwidValue(value)
    if value == "" then
        return false
    end
    local lower = value:lower():gsub("%s+", "")
    local exact = {
        ["unknown"] = true,
        ["none"] = true,
        ["null"] = true,
        ["spoof"] = true,
        ["spoofed"] = true,
        ["fakehwid"] = true,
        ["testhwid"] = true,
        ["randomhwid"] = true,
        ["00000000"] = true,
        ["11111111"] = true
    }
    if exact[lower] then
        return true
    end
    if lower:find("spoof", 1, true) or lower:find("fakehwid", 1, true) then
        return true
    end
    if #lower >= 8 and (
        lower:match("^0+$")
        or lower:match("^1+$")
        or lower:match("^x+$")
        or lower:match("^a+$")
        or lower:match("^f+$")
    ) then
        return true
    end
    return false
end
local function inspectHwidRuntime()
    local env = environment()
    local score = 0
    local reasons = {}
    local sampled = {}
    local seenFunctions = {}
    local hwidValues = {}
    for _, provider in ipairs(hwidProviders()) do
        local fn = provider.fn
        if type(fn) == "function" and not seenFunctions[fn] then
            seenFunctions[fn] = true
            local value, stable = sampleHwidProvider(fn)
            if not stable then
                score = score + 90
                table.insert(reasons, "unstable_provider")
            elseif value ~= "" then
                sampled[provider.name] = value
                if obviousSpoofValue(value) then
                    score = score + 90
                    table.insert(reasons, "placeholder_hwid")
                end
                if provider.kind == "hwid" then
                    hwidValues[value] = true
                end
            end
        end
    end
    local uniqueHwid = 0
    for _ in pairs(hwidValues) do
        uniqueHwid = uniqueHwid + 1
    end
    if uniqueHwid >= 2 then
        score = score + 80
        table.insert(reasons, "provider_mismatch")
    end
    local function inspectVariable(value)
        value = cleanHwidValue(value)
        if value ~= "" and obviousSpoofValue(value) then
            score = score + 90
            table.insert(reasons, "placeholder_variable")
        end
        return value
    end
    local variableValues = {
        inspectVariable(env.hwid),
        inspectVariable(env.HWID),
        inspectVariable(rawget(_G, "hwid")),
        inspectVariable(rawget(_G, "HWID"))
    }
    local stableHwid = nil
    for value in pairs(hwidValues) do
        stableHwid = stableHwid or value
    end
    if stableHwid then
        for _, value in ipairs(variableValues) do
            if value ~= "" and value ~= stableHwid then
                score = score + 25
                table.insert(reasons, "variable_mismatch")
                break
            end
        end
    end
    local suspiciousName = false
    pcall(function()
        local checked = 0
        for key, value in pairs(env) do
            checked = checked + 1
            if checked > 1000 then
                break
            end
            if value ~= nil and type(key) == "string" then
                local name = key:lower():gsub("[^a-z0-9_]", "")
                local hasHwid = name:find("hwid", 1, true) ~= nil
                local looksLikeSpoofer = name:find("spoof", 1, true)
                    or name:find("fake", 1, true)
                    or name:find("sethwid", 1, true)
                    or name:find("changehwid", 1, true)
                    or name:find("randomhwid", 1, true)
                if hasHwid and looksLikeSpoofer then
                    suspiciousName = true
                    break
                end
            end
        end
    end)
    if suspiciousName then
        score = score + 75
        table.insert(reasons, "spoofer_surface")
    end
    if score > 100 then
        score = 100
    end
    return {
        blocked = score >= 70,
        score = score,
        reason = reasons[1] or "clean"
    }
end
local function executorHwid()
    local env = environment()
    local seenFunctions = {}
    for _, provider in ipairs(hwidProviders()) do
        local fn = provider.fn
        if type(fn) == "function" and not seenFunctions[fn] then
            seenFunctions[fn] = true
            local value, stable = sampleHwidProvider(fn)
            if stable and value ~= "" then
                return value
            end
        end
    end
    for _, value in ipairs({env.hwid, env.HWID, rawget(_G, "hwid"), rawget(_G, "HWID")}) do
        value = cleanHwidValue(value)
        if value ~= "" then
            return value
        end
    end
    return ""
end
local function hwid() return executorHwid() end
local function request(options, json)
    local ok, result = pcall(requester, options)
    if not ok then error("[CS] HTTP request failed: " .. tostring(result)) end
    if type(result) ~= "table" then error("[CS] Invalid server response") end
    local status = tonumber(result.StatusCode or result.Status or result.status)
    local body = result.Body or result.body
    if status ~= 200 then
        local message = "HTTP " .. tostring(status or "unknown")
        if type(body) == "string" then
            local valid, decoded = pcall(HttpService.JSONDecode, HttpService, body)
            if valid and type(decoded) == "table" and type(decoded.error) == "string" then message = decoded.error end
        end
        error("[CS] " .. message)
    end
    if type(body) ~= "string" or body == "" then error("[CS] Empty response") end
    if not json then return body end
    local good, data = pcall(HttpService.JSONDecode, HttpService, body)
    assert(good and type(data) == "table", "[CS] Invalid JSON response")
    return data
end
local function start(rawKey)
    local key = tostring(rawKey or ""):upper():gsub("^%s+", ""):gsub("%s+$", "")
    assert(key ~= "", "[CS] Enter your PREMIUM key")
    assert(not inspectHwidRuntime().blocked, "[CS] HWID spoofing detected. Restart Roblox without HWID spoofer")
    local payload = {
        key = key,
        device_id = deviceId(),
        hwid = hwid(),
        device_token = read(files.token),
        executor = executorId(),
        job_id = tostring(game.JobId or ""),
        place_id = tonumber(game.PlaceId) or 0,
        user_id = Players.LocalPlayer and Players.LocalPlayer.UserId or 0,
        protocol = 4,
        client_nonce = hex64()
    }
    local license = request({Url = url .. "/api/license/verify", Method = "POST", Headers = {["Content-Type"] = "application/json", ["Accept"] = "application/json"}, Body = HttpService:JSONEncode(payload)}, true)
    assert(license.valid == true, "[CS] License invalid: " .. tostring(license.status or "unknown"))
    assert(type(license.session_token) == "string" and #license.session_token == 64, "[CS] Session token is missing")
    assert(type(license.stage2_grant) == "string" and #license.stage2_grant == 64, "[CS] Stage2 grant is missing")
    assert(tonumber(license.security_protocol) == 4, "[CS] Incompatible security protocol")
    if type(license.device_token) == "string" then save(files.token, license.device_token) end
    local stageSource = request({Url = url .. "/api/script/premium/stage2", Method = "GET", Headers = {["X-Script-Token"] = license.session_token, ["X-Stage2-Grant"] = license.stage2_grant, ["Accept"] = "text/plain"}}, false)
    local stageChunk, err = loadstring(stageSource)
    assert(type(stageChunk) == "function", "[CS] Stage2 compilation failed: " .. tostring(err))
    local stage2 = stageChunk()
    assert(type(stage2) == "function", "[CS] Invalid Stage2 response")
    local context, startErr = stage2({Request = requester, BaseUrl = url, Edition = "PREMIUM", Token = license.session_token, SessionExpiresAt = license.session_expires_at, License = license, SecurityProtocol = 4})
    assert(context, "[CS] Startup failed: " .. tostring(startErr))
    save(files.key, key)
    return context
end
local savedKey = read(files.key):upper():gsub("^%s+", ""):gsub("%s+$", "")
local autoError = nil
if savedKey ~= "" then
    local ok, context = pcall(start, savedKey)
    if ok then
        print("[CS] PREMIUM loaded from saved key")
        return context
    end
    autoError = tostring(context)
    warn("[CS] Automatic PREMIUM load failed: " .. autoError)
end
local Palette = {
    Window = Color3.fromRGB(4, 7, 11),
    Top = Color3.fromRGB(7, 11, 16),
    Surface = Color3.fromRGB(12, 18, 25),
    Surface2 = Color3.fromRGB(16, 24, 33),
    Border = Color3.fromRGB(48, 67, 86),
    Text = Color3.fromRGB(240, 245, 251),
    SubText = Color3.fromRGB(197, 209, 221),
    Dim = Color3.fromRGB(112, 129, 145),
    Accent = Color3.fromRGB(144, 176, 204),
    Error = Color3.fromRGB(225, 113, 126),
    Success = Color3.fromRGB(125, 209, 159)
}
local function rounded(instance, radius)
    local corner = Instance.new("UICorner")
    corner.CornerRadius = UDim.new(0, radius)
    corner.Parent = instance
end
local function outline(instance, color, transparency)
    local stroke = Instance.new("UIStroke")
    stroke.Color = color
    stroke.Transparency = transparency
    stroke.Thickness = 1
    stroke.Parent = instance
end
local function label(parent, text, size, position, font, textSize, color)
    local item = Instance.new("TextLabel")
    item.BackgroundTransparency = 1
    item.Text = text
    item.Size = size
    item.Position = position
    item.Font = font
    item.TextSize = textSize
    item.TextColor3 = color
    item.TextXAlignment = Enum.TextXAlignment.Left
    item.TextYAlignment = Enum.TextYAlignment.Center
    item.Parent = parent
    return item
end
local parent
if type(gethui) == "function" then
    local ok, value = pcall(gethui)
    if ok and typeof(value) == "Instance" then parent = value end
end
if not parent then parent = Players.LocalPlayer:WaitForChild("PlayerGui") end
local previous = parent:FindFirstChild("CyfraSenseKeySystem")
if previous then previous:Destroy() end
local gui = Instance.new("ScreenGui")
gui.Name = "CyfraSenseKeySystem"
gui.ResetOnSpawn = false
gui.IgnoreGuiInset = true
gui.DisplayOrder = 10000
gui.ZIndexBehavior = Enum.ZIndexBehavior.Sibling
gui.Parent = parent
local dim = Instance.new("Frame")
dim.Size = UDim2.fromScale(1, 1)
dim.BackgroundColor3 = Color3.new(0, 0, 0)
dim.BackgroundTransparency = 0.42
dim.BorderSizePixel = 0
dim.Parent = gui
local window = Instance.new("Frame")
window.AnchorPoint = Vector2.new(0.5, 0.5)
window.Position = UDim2.fromScale(0.5, 0.5)
window.Size = UDim2.fromOffset(500, 273)
window.BackgroundColor3 = Palette.Window
window.BorderSizePixel = 0
window.Parent = dim
rounded(window, 12)
outline(window, Palette.Border, 0.18)
local top = Instance.new("Frame")
top.Size = UDim2.new(1, 0, 0, 58)
top.BackgroundColor3 = Palette.Top
top.BorderSizePixel = 0
top.Parent = window
local line = Instance.new("Frame")
line.AnchorPoint = Vector2.new(0, 1)
line.Position = UDim2.new(0, 0, 1, 0)
line.Size = UDim2.new(1, 0, 0, 1)
line.BackgroundColor3 = Palette.Accent
line.BorderSizePixel = 0
line.Parent = top
local brandBox = Instance.new("Frame")
brandBox.Size = UDim2.fromOffset(34, 34)
brandBox.Position = UDim2.fromOffset(16, 12)
brandBox.BackgroundColor3 = Palette.Surface2
brandBox.BorderSizePixel = 0
brandBox.Parent = top
rounded(brandBox, 8)
outline(brandBox, Palette.Border, 0.18)
local brand = label(brandBox, "CS", UDim2.fromScale(1, 1), UDim2.new(), Enum.Font.GothamBold, 14, Palette.Text)
brand.TextXAlignment = Enum.TextXAlignment.Center
label(top, "CyfraSense", UDim2.fromOffset(190, 22), UDim2.fromOffset(62, 9), Enum.Font.GothamBold, 15, Palette.Text)
label(top, "PREMIUM loader", UDim2.fromOffset(240, 18), UDim2.fromOffset(62, 29), Enum.Font.Gotham, 11, Palette.Dim)
label(window, "License key", UDim2.fromOffset(200, 18), UDim2.fromOffset(24, 75), Enum.Font.GothamMedium, 11, Palette.SubText)
local box = Instance.new("TextBox")
box.Size = UDim2.new(1, -48, 0, 44)
box.Position = UDim2.fromOffset(24, 99)
box.BackgroundColor3 = Palette.Surface
box.BorderSizePixel = 0
box.ClearTextOnFocus = false
box.Font = Enum.Font.Code
box.TextSize = 13
box.TextColor3 = Palette.Text
box.PlaceholderColor3 = Palette.Dim
box.PlaceholderText = "CYFRA-XXXXX-XXXXX-XXXXX-XXXXX"
box.Text = savedKey
box.TextXAlignment = Enum.TextXAlignment.Left
box.Parent = window
rounded(box, 8)
outline(box, Palette.Border, 0.15)
local padding = Instance.new("UIPadding")
padding.PaddingLeft = UDim.new(0, 14)
padding.PaddingRight = UDim.new(0, 14)
padding.Parent = box
local statusLabel = label(window, "", UDim2.new(1, -48, 0, 38), UDim2.fromOffset(24, 150), Enum.Font.Gotham, 11, Palette.SubText)
statusLabel.TextWrapped = true
statusLabel.TextYAlignment = Enum.TextYAlignment.Top
local action = Instance.new("TextButton")
action.Size = UDim2.new(1, -48, 0, 42)
action.Position = UDim2.fromOffset(24, 192)
action.BackgroundColor3 = Palette.Surface2
action.BorderSizePixel = 0
action.AutoButtonColor = true
action.Font = Enum.Font.GothamBold
action.Text = "LOAD"
action.TextSize = 12
action.TextColor3 = Palette.Text
action.Parent = window
rounded(action, 8)
outline(action, Palette.Border, 0.08)
local footer = label(window, "Active PREMIUM license required", UDim2.new(1, -48, 0, 18), UDim2.fromOffset(24, 243), Enum.Font.Gotham, 10, Palette.Dim)
footer.TextXAlignment = Enum.TextXAlignment.Center
local function setStatus(value, color)
    statusLabel.Text = value
    statusLabel.TextColor3 = color or Palette.SubText
end
if autoError then
    setStatus("Auto-load failed: " .. autoError:sub(1, 170), Palette.Error)
else
    setStatus("Enter your PREMIUM key to continue.", Palette.SubText)
end
local gate = Instance.new("BindableEvent")
local busy = false
local function submit()
    if busy then return end
    local key = tostring(box.Text or ""):upper():gsub("^%s+", ""):gsub("%s+$", "")
    if key == "" then
        setStatus("Enter your PREMIUM license key.", Palette.Error)
        return
    end
    busy = true
    action.Active = false
    action.AutoButtonColor = false
    action.Text = "LOADING..."
    setStatus("Verifying license and loading PREMIUM...", Palette.SubText)
    task.spawn(function()
        local ok, result = pcall(start, key)
        if ok then
            setStatus("PREMIUM loaded.", Palette.Success)
            gui:Destroy()
            gate:Fire(result)
            return
        end
        setStatus(tostring(result):sub(1, 200), Palette.Error)
        action.Text = "LOAD"
        action.Active = true
        action.AutoButtonColor = true
        busy = false
    end)
end
action.Activated:Connect(submit)
box.FocusLost:Connect(function(enterPressed)
    if enterPressed then submit() end
end)
local context = gate.Event:Wait()
gate:Destroy()
print("[CS] CyfraSense PREMIUM loaded")
return context
