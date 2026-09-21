local HttpService = game:GetService("HttpService")

local Players = game:GetService("Players")

local UserInputService = game:GetService("UserInputService")

local BASE_URL = "http://144.91.74.116:34039"

local KEY_PATH = "CyfraSense/license.key"

local DEVICE_PATH = "CyfraSense/device.id"

local Palette = {

    Window = Color3.fromRGB(11, 12, 16),

    Top = Color3.fromRGB(15, 16, 22),

    Surface = Color3.fromRGB(18, 19, 25),

    Surface2 = Color3.fromRGB(23, 24, 31),

    Border = Color3.fromRGB(45, 47, 59),

    Text = Color3.fromRGB(239, 240, 245),

    SubText = Color3.fromRGB(157, 160, 174),

    Dim = Color3.fromRGB(103, 106, 120),

    White = Color3.fromRGB(248, 248, 250),

    Accent = Color3.fromRGB(125, 95, 255),

    Error = Color3.fromRGB(236, 100, 120),

    Success = Color3.fromRGB(114, 214, 150)

}

local function environment()

    return type(getgenv) == "function" and getgenv() or _G

end

local function requestFunction()

    local env = environment()

    local candidates = {

        env.request,

        env.http_request,

        rawget(_G, "request"),

        rawget(_G, "http_request")

    }

    if type(env.syn) == "table" then

        table.insert(candidates, env.syn.request)

    end

    if type(env.http) == "table" then

        table.insert(candidates, env.http.request)

    end

    for _, candidate in ipairs(candidates) do

        if type(candidate) == "function" then

            return candidate

        end

    end

    return nil

end

local requester = requestFunction()

assert(type(requester) == "function", "[CS] This executor does not provide a supported HTTP request function")

assert(type(loadstring) == "function", "[CS] loadstring is unavailable")

local function normalizeKey(value)

    return tostring(value or ""):upper():gsub("^%s+", ""):gsub("%s+$", "")

end

local function rounded(instance, radius)

    local corner = Instance.new("UICorner")

    corner.CornerRadius = UDim.new(0, radius)

    corner.Parent = instance

end

local function outline(instance, color, transparency)

    local stroke = Instance.new("UIStroke")

    stroke.Color = color

    stroke.Transparency = transparency or 0

    stroke.Thickness = 1

    stroke.Parent = instance

    return stroke

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

local function guiParent()

    if type(gethui) == "function" then

        local ok, parent = pcall(gethui)

        if ok and typeof(parent) == "Instance" then

            return parent

        end

    end

    local ok, coreGui = pcall(function()

        return game:GetService("CoreGui")

    end)

    if ok and coreGui then

        return coreGui

    end

    local player = Players.LocalPlayer or Players.PlayerAdded:Wait()

    return player:WaitForChild("PlayerGui")

end

local function decodeResponse(response, expectedType)

    if type(response) ~= "table" then

        return nil, "Invalid response from server."

    end

    local statusCode = tonumber(response.StatusCode or response.Status or response.status_code or response.status)

    local body = response.Body or response.body

    if statusCode ~= 200 then

        local message = "Server returned HTTP " .. tostring(statusCode or "unknown") .. "."

        if type(body) == "string" and body ~= "" then

            local ok, decoded = pcall(function()

                return HttpService:JSONDecode(body)

            end)

            if ok and type(decoded) == "table" and type(decoded.error) == "string" and decoded.error ~= "" then

                message = decoded.error

            end

        end

        return nil, message, statusCode

    end

    if expectedType == "text" then

        if type(body) ~= "string" or body == "" then

            return nil, "Server returned an empty response."

        end

        return body, nil, statusCode

    end

    if type(body) ~= "string" then

        return nil, "Server returned invalid JSON."

    end

    local ok, decoded = pcall(function()

        return HttpService:JSONDecode(body)

    end)

    if not ok or type(decoded) ~= "table" then

        return nil, "Server returned invalid JSON."

    end

    return decoded, nil, statusCode

end

local function performRequest(options, expectedType)

    local ok, response = pcall(requester, options)

    if not ok then

        return nil, tostring(response)

    end

    return decodeResponse(response, expectedType)

end

local function scriptHeaders(token)

    local headers = {

        ["Accept"] = "application/json",

        ["Cache-Control"] = "no-cache"

    }

    if type(token) == "string" and token ~= "" then

        headers["X-Script-Token"] = token

    end

    return headers

end

local function fetchManifest(edition, token)

    local data, err = performRequest({

        Url = BASE_URL .. "/api/script/" .. edition .. "/manifest",

        Method = "GET",

        Headers = scriptHeaders(token)

    }, "json")

    if not data then

        return nil, err

    end

    if type(data.version) ~= "string" or type(data.loader) ~= "string" or type(data.modules) ~= "table" then

        return nil, "Script manifest is invalid."

    end

    return data

end

local function fetchModule(edition, token, name)

    local headers = {

        ["Accept"] = "text/plain",

        ["Cache-Control"] = "no-cache"

    }

    if type(token) == "string" and token ~= "" then

        headers["X-Script-Token"] = token

    end

    return performRequest({

        Url = BASE_URL .. "/api/script/" .. edition .. "/module?name=" .. HttpService:UrlEncode(name),

        Method = "GET",

        Headers = headers

    }, "text")

end

local function verifyKey(key, deviceId)

    local payload = HttpService:JSONEncode({key = normalizeKey(key), device_id = deviceId})

    local data, err, statusCode = performRequest({

        Url = BASE_URL .. "/api/license/verify",

        Method = "POST",

        Headers = {

            ["Content-Type"] = "application/json",

            ["Accept"] = "application/json",

            ["Cache-Control"] = "no-cache"

        },

        Body = payload

    }, "json")

    if not data then

        if statusCode == 429 then

            return nil, "Too many verification attempts. Try again shortly."

        end

        return nil, err

    end

    local status = tostring(data.status or "invalid")

    if data.valid ~= true then

        if status == "expired" then

            return nil, "This license has expired.", status

        end

        if status == "revoked" then

            return nil, "This license has been revoked.", status

        end

        if status == "device_mismatch" then

            return nil, "This license is bound to another device. Reset HWID in the key panel.", status

        end

        if status == "device_required" then

            return nil, "Device binding failed. Update the CyfraSense launcher.", status

        end

        return nil, "Invalid license key.", "invalid"

    end

    if type(data.session_token) ~= "string" or not data.session_token:match("^[a-f0-9]+$") or #data.session_token ~= 64 then

        return nil, "License server did not return a valid script session."

    end

    if type(data.profile_id) ~= "string" or #data.profile_id ~= 24 or not data.profile_id:match("^[a-f0-9]+$") then

        return nil, "License server did not return a valid profile identity."

    end

    return data, nil, status

end

local function ensureCyfraSenseFolder()

    if type(makefolder) ~= "function" or type(isfolder) ~= "function" then

        return false

    end

    local ok = pcall(function()

        if not isfolder("CyfraSense") then

            makefolder("CyfraSense")

        end

    end)

    if not ok then

        return false

    end

    local checked, exists = pcall(isfolder, "CyfraSense")

    return checked and exists

end

local function validDeviceId(value)

    return type(value) == "string" and #value == 64 and value:match("^[a-f0-9]+$") ~= nil

end

local function generateDeviceId()

    local first = HttpService:GenerateGUID(false):gsub("-", ""):lower()

    local second = HttpService:GenerateGUID(false):gsub("-", ""):lower()

    return first .. second

end

local function readOrCreateDeviceId()

    if type(isfile) ~= "function" or type(readfile) ~= "function" or type(writefile) ~= "function" then

        return nil, "This executor does not provide persistent filesystem functions required for device binding."

    end

    local existsOk, exists = pcall(isfile, DEVICE_PATH)

    if existsOk and exists then

        local readOk, value = pcall(readfile, DEVICE_PATH)

        if readOk then

            value = tostring(value or ""):lower():gsub("^%s+", ""):gsub("%s+$", "")

            if validDeviceId(value) then

                return value

            end

        end

    end

    if not ensureCyfraSenseFolder() then

        return nil, "Could not create the CyfraSense data folder for device binding."

    end

    local value = generateDeviceId()

    local writeOk = pcall(writefile, DEVICE_PATH, value)

    if not writeOk then

        return nil, "Could not save the CyfraSense device identity."

    end

    return value

end

local function readSavedKey()

    if type(isfile) ~= "function" or type(readfile) ~= "function" then

        return ""

    end

    local ok, exists = pcall(isfile, KEY_PATH)

    if not ok or not exists then

        return ""

    end

    local readOk, value = pcall(readfile, KEY_PATH)

    if not readOk or type(value) ~= "string" then

        return ""

    end

    return normalizeKey(value)

end

local function saveKey(key)

    if type(writefile) ~= "function" then

        return false

    end

    ensureCyfraSenseFolder()

    return pcall(writefile, KEY_PATH, normalizeKey(key))

end

local function clearSavedKey()

    if type(isfile) == "function" and type(delfile) == "function" then

        local ok, exists = pcall(isfile, KEY_PATH)

        if ok and exists then

            pcall(delfile, KEY_PATH)

            return

        end

    end

    if type(writefile) == "function" then

        ensureCyfraSenseFolder()

        pcall(writefile, KEY_PATH, "")

    end

end

local function startScript(edition, license)

    local lowerEdition = tostring(edition):lower()

    local token = license and tostring(license.session_token or "") or ""

    local manifest, manifestError = fetchManifest(lowerEdition, token)

    if not manifest then

        return nil, manifestError

    end

    local loaderSource, loaderError = fetchModule(lowerEdition, token, manifest.loader)

    if not loaderSource then

        return nil, loaderError

    end

    local loaderChunk, compileError = loadstring(loaderSource, "@CyfraSense/remote/loader.lua")

    if type(loaderChunk) ~= "function" then

        return nil, "Could not compile remote loader: " .. tostring(compileError)

    end

    local ok, loader = pcall(loaderChunk)

    if not ok then

        return nil, "Remote loader failed: " .. tostring(loader)

    end

    if type(loader) ~= "table" or type(loader.Start) ~= "function" then

        return nil, "Remote loader returned an invalid module."

    end

    local licenseContext

    local configUrl = ""

    if edition == "PREMIUM" then

        licenseContext = {

            Authorized = true,

            Tier = "PREMIUM",

            Status = tostring(license.status or "active"),

            ExpiresAt = tonumber(license.expires_at),

            ScriptVersion = tostring(license.script_version or manifest.version),

            ProfileId = tostring(license.profile_id or "")

        }

        configUrl = BASE_URL .. "/api/script/premium/config"

    else

        licenseContext = {

            Authorized = true,

            Tier = "FREE",

            Status = "free",

            ScriptVersion = tostring(manifest.version)

        }

    end

    local started, context = pcall(function()

        return loader:Start({

            Request = requester,

            Token = token,

            Manifest = manifest,

            ModuleUrl = BASE_URL .. "/api/script/" .. lowerEdition .. "/module",

            ConfigUrl = configUrl,

            SessionExpiresAt = license and tonumber(license.session_expires_at) or nil,

            License = licenseContext

        })

    end)

    if not started then

        return nil, tostring(context)

    end

    return context

end

local function startPremium(key)

    key = normalizeKey(key)

    if key == "" then

        return nil, "Enter a license key.", "empty"

    end

    local deviceId, deviceError = readOrCreateDeviceId()

    if not deviceId then

        return nil, deviceError, "device"

    end

    local license, verifyError, status = verifyKey(key, deviceId)

    if not license then

        return nil, verifyError, status

    end

    local context, startError = startScript("PREMIUM", license)

    if not context then

        return nil, startError, "script"

    end

    saveKey(key)

    return context, nil, "active"

end

local function startFree()

    local context, err = startScript("FREE", nil)

    if not context then

        return nil, err, "script"

    end

    return context, nil, "free"

end

local savedKey = readSavedKey()

local parent = guiParent()

local existing = parent:FindFirstChild("CyfraSenseKeySystem")

if existing then

    existing:Destroy()

end

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

dim.BackgroundTransparency = 0.35

dim.BorderSizePixel = 0

dim.Parent = gui

local window = Instance.new("Frame")

window.AnchorPoint = Vector2.new(0.5, 0.5)

window.Position = UDim2.fromScale(0.5, 0.5)

window.Size = UDim2.fromOffset(500, 356)

window.BackgroundColor3 = Palette.Window

window.BorderSizePixel = 0

window.Parent = dim

rounded(window, 12)

outline(window, Palette.Border, 0.05)

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

brandBox.BackgroundColor3 = Palette.Accent

brandBox.BorderSizePixel = 0

brandBox.Parent = top

rounded(brandBox, 8)

local brand = label(brandBox, "CS", UDim2.fromScale(1, 1), UDim2.new(), Enum.Font.GothamBlack, 15, Palette.White)

brand.TextXAlignment = Enum.TextXAlignment.Center

label(top, "CyfraSense", UDim2.fromOffset(190, 22), UDim2.fromOffset(62, 9), Enum.Font.GothamBold, 15, Palette.Text)

label(top, "Choose script version", UDim2.fromOffset(240, 18), UDim2.fromOffset(62, 29), Enum.Font.Gotham, 11, Palette.Dim)

label(window, "Version", UDim2.fromOffset(200, 18), UDim2.fromOffset(24, 76), Enum.Font.GothamMedium, 11, Palette.SubText)

local freeButton = Instance.new("TextButton")

freeButton.Size = UDim2.new(0.5, -30, 0, 42)

freeButton.Position = UDim2.fromOffset(24, 99)

freeButton.BorderSizePixel = 0

freeButton.AutoButtonColor = true

freeButton.Font = Enum.Font.GothamBold

freeButton.Text = "FREE"

freeButton.TextSize = 12

freeButton.TextColor3 = Palette.Text

freeButton.Parent = window

rounded(freeButton, 8)

local freeStroke = outline(freeButton, Palette.Border, 0.15)

local premiumButton = Instance.new("TextButton")

premiumButton.AnchorPoint = Vector2.new(1, 0)

premiumButton.Size = UDim2.new(0.5, -30, 0, 42)

premiumButton.Position = UDim2.new(1, -24, 0, 99)

premiumButton.BorderSizePixel = 0

premiumButton.AutoButtonColor = true

premiumButton.Font = Enum.Font.GothamBold

premiumButton.Text = "PREMIUM"

premiumButton.TextSize = 12

premiumButton.TextColor3 = Palette.Text

premiumButton.Parent = window

rounded(premiumButton, 8)

local premiumStroke = outline(premiumButton, Palette.Border, 0.15)

local keyLabel = label(window, "License key", UDim2.fromOffset(200, 18), UDim2.fromOffset(24, 155), Enum.Font.GothamMedium, 11, Palette.SubText)

local box = Instance.new("TextBox")

box.Size = UDim2.new(1, -48, 0, 44)

box.Position = UDim2.fromOffset(24, 179)

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

local statusLabel = label(window, "", UDim2.new(1, -48, 0, 34), UDim2.fromOffset(24, 232), Enum.Font.Gotham, 11, Palette.SubText)

statusLabel.TextWrapped = true

statusLabel.TextYAlignment = Enum.TextYAlignment.Top

local action = Instance.new("TextButton")

action.Size = UDim2.new(1, -48, 0, 42)

action.Position = UDim2.fromOffset(24, 277)

action.BackgroundColor3 = Palette.Accent

action.BorderSizePixel = 0

action.AutoButtonColor = true

action.Font = Enum.Font.GothamBold

action.TextSize = 12

action.TextColor3 = Palette.White

action.Parent = window

rounded(action, 8)

local footer = label(window, "", UDim2.new(1, -48, 0, 18), UDim2.fromOffset(24, 329), Enum.Font.Gotham, 10, Palette.Dim)

footer.TextXAlignment = Enum.TextXAlignment.Center

local gate = Instance.new("BindableEvent")

local connections = {}

local busy = false

local completed = false

local loadedContext = nil

local selectedMode = savedKey ~= "" and "PREMIUM" or "FREE"

local function setStatus(text, color)

    if statusLabel and statusLabel.Parent then

        statusLabel.Text = text

        statusLabel.TextColor3 = color or Palette.SubText

    end

end

local function refreshMode()

    local freeSelected = selectedMode == "FREE"

    freeButton.BackgroundColor3 = freeSelected and Palette.Accent or Palette.Surface2

    premiumButton.BackgroundColor3 = freeSelected and Palette.Surface2 or Palette.Accent

    freeButton.TextColor3 = freeSelected and Palette.White or Palette.SubText

    premiumButton.TextColor3 = freeSelected and Palette.SubText or Palette.White

    freeStroke.Color = freeSelected and Palette.Accent or Palette.Border

    premiumStroke.Color = freeSelected and Palette.Border or Palette.Accent

    keyLabel.Visible = not freeSelected

    box.Visible = not freeSelected

    if freeSelected then

        action.Text = "Load FREE"

        footer.Text = "FREE does not require a license key."

        setStatus("Load the free version without license verification.", Palette.SubText)

    else

        action.Text = "Verify & load PREMIUM"

        footer.Text = "PREMIUM requires an active CyfraSense license."

        setStatus("Enter your Premium license key to continue.", Palette.SubText)

    end

end

local function chooseMode(mode)

    if busy or completed then

        return

    end

    selectedMode = mode

    refreshMode()

    if mode == "PREMIUM" then

        pcall(function()

            box:CaptureFocus()

        end)

    else

        pcall(function()

            box:ReleaseFocus()

        end)

    end

end

local function submit()

    if busy or completed then

        return

    end

    busy = true

    action.AutoButtonColor = false

    if selectedMode == "FREE" then

        action.Text = "Loading FREE..."

        setStatus("Loading CyfraSense FREE...", Palette.SubText)

        task.spawn(function()

            gui.Enabled = false

            local context, err = startFree()

            if context then

                loadedContext = context

                completed = true

                action.Text = "Loaded"

                setStatus("CyfraSense FREE loaded.", Palette.Success)

                task.wait(0.15)

                gate:Fire(true)

                return

            end

            gui.Enabled = true

            setStatus(err or "Could not load CyfraSense FREE.", Palette.Error)

            action.Text = "Load FREE"

            action.AutoButtonColor = true

            busy = false

        end)

        return

    end

    local key = normalizeKey(box.Text)

    if key == "" then

        setStatus("Enter a license key.", Palette.Error)

        action.Text = "Verify & load PREMIUM"

        action.AutoButtonColor = true

        busy = false

        return

    end

    action.Text = "Verifying..."

    setStatus("Checking license and loading CyfraSense PREMIUM...", Palette.SubText)

    task.spawn(function()

        gui.Enabled = false

        local context, err, state = startPremium(key)

        if context then

            loadedContext = context

            completed = true

            action.Text = "Loaded"

            setStatus("Premium license active. CyfraSense loaded.", Palette.Success)

            task.wait(0.15)

            gate:Fire(true)

            return

        end

        if state == "invalid" or state == "expired" or state == "revoked" then

            clearSavedKey()

        end

        gui.Enabled = true

        setStatus(err or "Could not load CyfraSense PREMIUM.", Palette.Error)

        action.Text = "Verify & load PREMIUM"

        action.AutoButtonColor = true

        busy = false

    end)

end

table.insert(connections, freeButton.MouseButton1Click:Connect(function()

    chooseMode("FREE")

end))

table.insert(connections, premiumButton.MouseButton1Click:Connect(function()

    chooseMode("PREMIUM")

end))

table.insert(connections, action.MouseButton1Click:Connect(submit))

table.insert(connections, box.FocusLost:Connect(function(enterPressed)

    if enterPressed and selectedMode == "PREMIUM" then

        submit()

    end

end))

table.insert(connections, UserInputService.InputBegan:Connect(function(input, processed)

    if not processed and input.KeyCode == Enum.KeyCode.Return and selectedMode == "PREMIUM" and box:IsFocused() then

        submit()

    end

end))

table.insert(connections, gui.AncestryChanged:Connect(function(_, newParent)

    if not newParent and not completed then

        gate:Fire(false)

    end

end))

refreshMode()

if selectedMode == "PREMIUM" then

    pcall(function()

        box:CaptureFocus()

    end)

end

local accepted = gate.Event:Wait()

gate:Destroy()

for _, connection in ipairs(connections) do

    connection:Disconnect()

end

if gui and gui.Parent then

    gui:Destroy()

end

assert(accepted and loadedContext, "[CS] Script selection was cancelled")

print("[CS] CyfraSense " .. selectedMode .. " loaded.")

return loadedContext
