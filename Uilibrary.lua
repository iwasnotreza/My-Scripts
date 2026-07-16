local Paradise = {}
Paradise.__index = Paradise

local TweenService = game:GetService("TweenService")
local UserInputService = game:GetService("UserInputService")
local Players = game:GetService("Players")
local LocalPlayer = Players.LocalPlayer
local PlayerGui = LocalPlayer:WaitForChild("PlayerGui")

local Theme = {
    Background = Color3.fromRGB(16, 18, 23),
    TopBar     = Color3.fromRGB(20, 22, 28),
    Sidebar    = Color3.fromRGB(18, 20, 25),
    ElementBG  = Color3.fromRGB(24, 26, 32),
    Stroke     = Color3.fromRGB(40, 42, 50),
    Accent     = Color3.fromRGB(90, 130, 255),
    TextColor  = Color3.fromRGB(240, 240, 240),
    SubText    = Color3.fromRGB(150, 150, 150),
}

local function new(class, props)
    local i = Instance.new(class)
    for k, v in pairs(props) do i[k] = v end
    return i
end

local function tw(inst, props, t)
    TweenService:Create(inst, TweenInfo.new(t or 0.2, Enum.EasingStyle.Quad), props):Play()
end

local function drag(frame, handle)
    local dragging, dragInput, dragStart, startPos
    handle.InputBegan:Connect(function(input)
        if input.UserInputType == Enum.UserInputType.MouseButton1 or input.UserInputType == Enum.UserInputType.Touch then
            dragging = true
            dragStart = input.Position
            startPos = frame.Position
            input.Changed:Connect(function()
                if input.UserInputState == Enum.UserInputState.End then dragging = false end
            end)
        end
    end)
    handle.InputChanged:Connect(function(input)
        if input.UserInputType == Enum.UserInputType.MouseMovement or input.UserInputType == Enum.UserInputType.Touch then
            dragInput = input
        end
    end)
    UserInputService.InputChanged:Connect(function(input)
        if input == dragInput and dragging then
            local delta = input.Position - dragStart
            frame.Position = UDim2.new(startPos.X.Scale, startPos.X.Offset + delta.X, startPos.Y.Scale, startPos.Y.Offset + delta.Y)
        end
    end)
end

function Paradise.new(title, logoId, version)
    if PlayerGui:FindFirstChild("ParadiseHub") then PlayerGui.ParadiseHub:Destroy() end

    local ScreenGui = new("ScreenGui", {Name = "ParadiseHub", Parent = PlayerGui, ResetOnSpawn = false, DisplayOrder = 999})

    local Main = new("Frame", {
        Size = UDim2.new(0,700,0,420), Position = UDim2.new(0.5,-350,0.5,-210),
        BackgroundColor3 = Theme.Background, BorderSizePixel = 0, ClipsDescendants = true, Parent = ScreenGui
    })
    new("UICorner", {CornerRadius = UDim.new(0,8), Parent = Main})
    new("UIStroke", {Color = Theme.Stroke, Parent = Main})
    new("UIGradient", {
        Color = ColorSequence.new({ColorSequenceKeypoint.new(0, Color3.fromRGB(26,28,35)), ColorSequenceKeypoint.new(1, Color3.fromRGB(10,11,15))}),
        Rotation = 80, Parent = Main
    })

    local Welcome = new("TextLabel", {
        Size = UDim2.new(1,0,0,40), Position = UDim2.new(0,0,0,0), BackgroundColor3 = Theme.Accent,
        BackgroundTransparency = 0.15, Text = "Welcome, " .. LocalPlayer.Name .. "!",
        Font = Enum.Font.GothamBold, TextSize = 16, TextColor3 = Color3.new(1,1,1), ZIndex = 20, Parent = Main
    })
    task.spawn(function()
        task.wait(2)
        tw(Welcome, {BackgroundTransparency = 1, TextTransparency = 1}, 0.5)
        task.wait(0.5)
        Welcome:Destroy()
    end)

    local TopBar = new("Frame", {Size = UDim2.new(1,0,0,42), BackgroundColor3 = Theme.TopBar, BorderSizePixel = 0, Parent = Main})
    new("UICorner", {CornerRadius = UDim.new(0,8), Parent = TopBar})
    new("Frame", {Size = UDim2.new(1,0,0,10), Position = UDim2.new(0,0,1,-10), BackgroundColor3 = Theme.TopBar, BorderSizePixel = 0, Parent = TopBar})
    new("UIGradient", {
        Color = ColorSequence.new({ColorSequenceKeypoint.new(0, Theme.Accent), ColorSequenceKeypoint.new(1, Theme.TopBar)}),
        Transparency = NumberSequence.new({NumberSequenceKeypoint.new(0,0.85), NumberSequenceKeypoint.new(1,1)}),
        Parent = TopBar
    })

    local Logo = new("ImageLabel", {
        Size = UDim2.new(0,26,0,26), Position = UDim2.new(0,10,0.5,-13),
        BackgroundTransparency = 1, Image = logoId or "", ScaleType = Enum.ScaleType.Fit, Parent = TopBar
    })
    new("UICorner", {CornerRadius = UDim.new(1,0), Parent = Logo})

    new("TextLabel", {
        Size = UDim2.new(1,-160,1,0), Position = UDim2.new(0,45,0,0), BackgroundTransparency = 1,
        Text = title or "Paradise Hub", Font = Enum.Font.GothamBold, TextSize = 16, TextColor3 = Theme.TextColor,
        TextXAlignment = Enum.TextXAlignment.Left, Parent = TopBar
    })

    local MinBtn = new("TextButton", {
        Size = UDim2.new(0,30,0,26), Position = UDim2.new(1,-74,0.5,-13), BackgroundColor3 = Theme.ElementBG,
        Text = "—", Font = Enum.Font.GothamBold, TextSize = 16, TextColor3 = Theme.TextColor, AutoButtonColor = false, Parent = TopBar
    })
    new("UICorner", {CornerRadius = UDim.new(0,4), Parent = MinBtn})
    new("UIStroke", {Color = Theme.Stroke, Parent = MinBtn})

    local CloseBtn = new("TextButton", {
        Size = UDim2.new(0,30,0,26), Position = UDim2.new(1,-38,0.5,-13), BackgroundColor3 = Theme.ElementBG,
        Text = "×", Font = Enum.Font.GothamBold, TextSize = 18, TextColor3 = Theme.TextColor, AutoButtonColor = false, Parent = TopBar
    })
    new("UICorner", {CornerRadius = UDim.new(0,4), Parent = CloseBtn})
    new("UIStroke", {Color = Theme.Stroke, Parent = CloseBtn})

    MinBtn.MouseEnter:Connect(function() tw(MinBtn, {BackgroundColor3 = Theme.Sidebar}) end)
    MinBtn.MouseLeave:Connect(function() tw(MinBtn, {BackgroundColor3 = Theme.ElementBG}) end)
    CloseBtn.MouseEnter:Connect(function() tw(CloseBtn, {BackgroundColor3 = Color3.fromRGB(200,60,60)}) end)
    CloseBtn.MouseLeave:Connect(function() tw(CloseBtn, {BackgroundColor3 = Theme.ElementBG}) end)

    local Body = new("Frame", {Size = UDim2.new(1,0,1,-72), Position = UDim2.new(0,0,0,42), BackgroundTransparency = 1, Parent = Main})
    local Sidebar = new("Frame", {Size = UDim2.new(0,150,1,0), BackgroundColor3 = Theme.Sidebar, BorderSizePixel = 0, Parent = Body})
    new("Frame", {Size = UDim2.new(0,1,1,0), Position = UDim2.new(1,0,0,0), BackgroundColor3 = Theme.Stroke, BorderSizePixel = 0, Parent = Sidebar})
    new("UIListLayout", {Padding = UDim.new(0,2), Parent = Sidebar})
    new("UIPadding", {PaddingTop = UDim.new(0,8), Parent = Sidebar})

    local ContentArea = new("Frame", {Size = UDim2.new(1,-150,1,0), Position = UDim2.new(0,150,0,0), BackgroundTransparency = 1, Parent = Body})

    local BottomBar = new("Frame", {Size = UDim2.new(1,0,0,30), Position = UDim2.new(0,0,1,-30), BackgroundColor3 = Theme.TopBar, BorderSizePixel = 0, Parent = Main})
    new("UICorner", {CornerRadius = UDim.new(0,8), Parent = BottomBar})
    new("Frame", {Size = UDim2.new(1,0,0,10), BackgroundColor3 = Theme.TopBar, BorderSizePixel = 0, Parent = BottomBar})

    new("TextLabel", {
        Size = UDim2.new(0,200,1,0), Position = UDim2.new(0,12,0,0), BackgroundTransparency = 1,
        Text = version or "Version 1.0", Font = Enum.Font.Gotham, TextSize = 12, TextColor3 = Theme.SubText,
        TextXAlignment = Enum.TextXAlignment.Left, Parent = BottomBar
    })

    new("TextLabel", {
        Size = UDim2.new(0,200,1,0), Position = UDim2.new(1,-212,0,0), BackgroundTransparency = 1,
        Font = Enum.Font.Gotham, TextSize = 12, TextXAlignment = Enum.TextXAlignment.Right, RichText = true,
        Text = '<font color="#aaaaaa">Status: </font><font color="#50DC78">Connected</font>', Parent = BottomBar
    })

    drag(Main, TopBar)

    local ReopenBtn = new("TextButton", {
        Size = UDim2.new(0,50,0,50), Position = UDim2.new(0,20,0,20), BackgroundColor3 = Theme.ElementBG,
        Text = "P", Font = Enum.Font.GothamBold, TextSize = 18, TextColor3 = Theme.TextColor,
        Visible = false, AutoButtonColor = false, Parent = ScreenGui
    })
    new("UICorner", {CornerRadius = UDim.new(1,0), Parent = ReopenBtn})
    new("UIStroke", {Color = Theme.Accent, Thickness = 2, Parent = ReopenBtn})
    drag(ReopenBtn, ReopenBtn)

    MinBtn.MouseButton1Click:Connect(function()
        tw(Main, {Size = UDim2.new(0,0,0,0)}, 0.2)
        task.wait(0.2)
        Main.Visible = false
        ReopenBtn.Visible = true
    end)
    ReopenBtn.MouseButton1Click:Connect(function()
        Main.Visible = true
        Main.Size = UDim2.new(0,0,0,0)
        tw(Main, {Size = UDim2.new(0,700,0,420)}, 0.2)
        ReopenBtn.Visible = false
    end)
    CloseBtn.MouseButton1Click:Connect(function() ScreenGui:Destroy() end)

    local Window = {_first = true, _tabs = {}}

    function Window:Tab(name)
        local TabBtn = new("TextButton", {Size = UDim2.new(1,0,0,38), BackgroundTransparency = 1, Text = "", AutoButtonColor = false, Parent = Sidebar})
        local Bar = new("Frame", {Size = UDim2.new(0,3,1,0), BackgroundColor3 = Theme.Accent, Visible = false, Parent = TabBtn})
        local Lbl = new("TextLabel", {
            Size = UDim2.new(1,-20,1,0), Position = UDim2.new(0,15,0,0), BackgroundTransparency = 1,
            Text = name, Font = Enum.Font.Gotham, TextSize = 14, TextColor3 = Theme.SubText,
            TextXAlignment = Enum.TextXAlignment.Left, Parent = TabBtn
        })

        local Page = new("ScrollingFrame", {
            Size = UDim2.new(1,0,1,0), BackgroundTransparency = 1, BorderSizePixel = 0,
            ScrollBarThickness = 3, ScrollBarImageColor3 = Theme.Accent,
            AutomaticCanvasSize = Enum.AutomaticSize.Y, CanvasSize = UDim2.new(0,0,0,0),
            Visible = false, Parent = ContentArea
        })
        new("UIPadding", {PaddingTop = UDim.new(0,15), PaddingLeft = UDim.new(0,15), PaddingRight = UDim.new(0,15), PaddingBottom = UDim.new(0,15), Parent = Page})
        new("UIListLayout", {Padding = UDim.new(0,10), Parent = Page})

        local function select()
            for _, t in pairs(Window._tabs) do
                t.Page.Visible = false; t.Bar.Visible = false
                tw(t.Lbl, {TextColor3 = Theme.SubText}, 0.15)
            end
            Page.Visible = true; Bar.Visible = true
            tw(Lbl, {TextColor3 = Theme.TextColor}, 0.15)
        end
        TabBtn.MouseButton1Click:Connect(select)
        table.insert(Window._tabs, {Page = Page, Bar = Bar, Lbl = Lbl})
        if Window._first then select(); Window._first = false end

        local Tab = {}
        local function box(h)
            local H = new("Frame", {Size = UDim2.new(1,0,0,h), BackgroundColor3 = Theme.ElementBG, BorderSizePixel = 0, Parent = Page})
            new("UICorner", {CornerRadius = UDim.new(0,6), Parent = H})
            new("UIStroke", {Color = Theme.Stroke, Parent = H})
            return H
        end

        function Tab:Label(text)
            local H = box(30); H.BackgroundTransparency = 1
            new("TextLabel", {Size = UDim2.new(1,0,1,0), BackgroundTransparency = 1, Text = text, Font = Enum.Font.Gotham, TextSize = 14, TextColor3 = Theme.SubText, TextXAlignment = Enum.TextXAlignment.Left, Parent = H})
        end

        function Tab:Section(text)
            local H = new("Frame", {Size = UDim2.new(1,0,0,25), BackgroundTransparency = 1, Parent = Page})
            new("TextLabel", {Size = UDim2.new(1,0,1,0), BackgroundTransparency = 1, Text = text, Font = Enum.Font.GothamBold, TextSize = 13, TextColor3 = Theme.Accent, TextXAlignment = Enum.TextXAlignment.Left, Parent = H})
        end

        function Tab:Button(text, callback)
            local H = box(36)
            local B = new("TextButton", {Size = UDim2.new(1,0,1,0), BackgroundTransparency = 1, Text = text, Font = Enum.Font.Gotham, TextSize = 14, TextColor3 = Theme.TextColor, AutoButtonColor = false, Parent = H})
            B.MouseButton1Click:Connect(function()
                tw(H, {BackgroundColor3 = Theme.Accent}, 0.1)
                task.wait(0.1)
                tw(H, {BackgroundColor3 = Theme.ElementBG}, 0.2)
                if callback then callback() end
            end)
        end

        function Tab:Toggle(text, default, callback)
            local state = default or false
            local H = box(36)
            new("TextLabel", {Size = UDim2.new(1,-60,1,0), Position = UDim2.new(0,12,0,0), BackgroundTransparency = 1, Text = text, Font = Enum.Font.Gotham, TextSize = 14, TextColor3 = Theme.TextColor, TextXAlignment = Enum.TextXAlignment.Left, Parent = H})
            local Sw = new("Frame", {Size = UDim2.new(0,40,0,20), Position = UDim2.new(1,-50,0.5,-10), BackgroundColor3 = state and Theme.Accent or Color3.fromRGB(50,52,58), Parent = H})
            new("UICorner", {CornerRadius = UDim.new(1,0), Parent = Sw})
            local C = new("Frame", {Size = UDim2.new(0,16,0,16), Position = state and UDim2.new(1,-18,0.5,-8) or UDim2.new(0,2,0.5,-8), BackgroundColor3 = Color3.new(1,1,1), Parent = Sw})
            new("UICorner", {CornerRadius = UDim.new(1,0), Parent = C})
            local Click = new("TextButton", {Size = UDim2.new(1,0,1,0), BackgroundTransparency = 1, Text = "", Parent = H})
            Click.MouseButton1Click:Connect(function()
                state = not state
                tw(Sw, {BackgroundColor3 = state and Theme.Accent or Color3.fromRGB(50,52,58)}, 0.15)
                tw(C, {Position = state and UDim2.new(1,-18,0.5,-8) or UDim2.new(0,2,0.5,-8)}, 0.15)
                if callback then callback(state) end
            end)
        end

        function Tab:Slider(text, min, max, default, callback)
            local value = default or min
            local H = box(50)
            new("TextLabel", {Size = UDim2.new(1,-20,0,20), Position = UDim2.new(0,12,0,4), BackgroundTransparency = 1, Text = text, Font = Enum.Font.Gotham, TextSize = 14, TextColor3 = Theme.TextColor, TextXAlignment = Enum.TextXAlignment.Left, Parent = H})
            local ValLbl = new("TextLabel", {Size = UDim2.new(0,50,0,20), Position = UDim2.new(1,-62,0,4), BackgroundTransparency = 1, Text = tostring(value), Font = Enum.Font.Gotham, TextSize = 13, TextColor3 = Theme.SubText, TextXAlignment = Enum.TextXAlignment.Right, Parent = H})
            local Track = new("Frame", {Size = UDim2.new(1,-24,0,6), Position = UDim2.new(0,12,1,-16), BackgroundColor3 = Color3.fromRGB(50,52,58), Parent = H})
            new("UICorner", {CornerRadius = UDim.new(1,0), Parent = Track})
            local Fill = new("Frame", {Size = UDim2.new((value-min)/(max-min),0,1,0), BackgroundColor3 = Theme.Accent, Parent = Track})
            new("UICorner", {CornerRadius = UDim.new(1,0), Parent = Fill})
            local dragging = false
            Track.InputBegan:Connect(function(i) if i.UserInputType == Enum.UserInputType.MouseButton1 or i.UserInputType == Enum.UserInputType.Touch then dragging = true end end)
            UserInputService.InputEnded:Connect(function(i) if i.UserInputType == Enum.UserInputType.MouseButton1 or i.UserInputType == Enum.UserInputType.Touch then dragging = false end end)
            local function upd(pos)
                local rel = math.clamp((pos.X - Track.AbsolutePosition.X) / Track.AbsoluteSize.X, 0, 1)
                value = math.floor(min + (max-min)*rel)
                Fill.Size = UDim2.new(rel,0,1,0)
                ValLbl.Text = tostring(value)
                if callback then callback(value) end
            end
            UserInputService.InputChanged:Connect(function(i) if dragging and (i.UserInputType == Enum.UserInputType.MouseMovement or i.UserInputType == Enum.UserInputType.Touch) then upd(i.Position) end end)
            Track.InputBegan:Connect(function(i) if i.UserInputType == Enum.UserInputType.MouseButton1 or i.UserInputType == Enum.UserInputType.Touch then upd(i.Position) end end)
        end

        function Tab:Dropdown(text, options, callback)
            local open = false
            local H = box(36); H.ClipsDescendants = false
            new("TextLabel", {Size = UDim2.new(0.5,0,1,0), Position = UDim2.new(0,12,0,0), BackgroundTransparency = 1, Text = text, Font = Enum.Font.Gotham, TextSize = 14, TextColor3 = Theme.TextColor, TextXAlignment = Enum.TextXAlignment.Left, Parent = H})
            local Sel = new("TextButton", {Size = UDim2.new(0.4,0,0,26), Position = UDim2.new(1,-12,0.5,-13), AnchorPoint = Vector2.new(1,0), BackgroundColor3 = Color3.fromRGB(30,32,38), Text = options[1] or "None", Font = Enum.Font.Gotham, TextSize = 13, TextColor3 = Theme.TextColor, AutoButtonColor = false, Parent = H})
            new("UICorner", {CornerRadius = UDim.new(0,4), Parent = Sel})
            local List = new("Frame", {Size = UDim2.new(0.4,0,0,#options*26), Position = UDim2.new(1,-12,1,4), AnchorPoint = Vector2.new(1,0), BackgroundColor3 = Color3.fromRGB(30,32,38), Visible = false, ZIndex = 5, Parent = H})
            new("UICorner", {CornerRadius = UDim.new(0,4), Parent = List})
            new("UIListLayout", {Parent = List})
            for _, opt in ipairs(options) do
                local Ob = new("TextButton", {Size = UDim2.new(1,0,0,26), BackgroundTransparency = 1, Text = opt, Font = Enum.Font.Gotham, TextSize = 13, TextColor3 = Theme.SubText, ZIndex = 5, Parent = List})
                Ob.MouseButton1Click:Connect(function()
                    Sel.Text = opt; List.Visible = false; open = false
                    if callback then callback(opt) end
                end)
            end
            Sel.MouseButton1Click:Connect(function() open = not open; List.Visible = open end)
        end

        function Tab:Input(placeholder, callback)
            local H = box(36)
            local Box = new("TextBox", {
                Size = UDim2.new(1,-24,1,0), Position = UDim2.new(0,12,0,0), BackgroundTransparency = 1,
                PlaceholderText = placeholder or "Type here...", Text = "", Font = Enum.Font.Gotham, TextSize = 14,
                TextColor3 = Theme.TextColor, PlaceholderColor3 = Theme.SubText, ClearTextOnFocus = false,
                TextXAlignment = Enum.TextXAlignment.Left, Parent = H
            })
            Box.FocusLost:Connect(function(enter)
                if enter and callback then callback(Box.Text) end
            end)
        end

        function Tab:Keybind(text, defaultKey, callback)
            local key = defaultKey or Enum.KeyCode.RightShift
            local listening = false
            local H = box(36)
            new("TextLabel", {Size = UDim2.new(1,-90,1,0), Position = UDim2.new(0,12,0,0), BackgroundTransparency = 1, Text = text, Font = Enum.Font.Gotham, TextSize = 14, TextColor3 = Theme.TextColor, TextXAlignment = Enum.TextXAlignment.Left, Parent = H})
            local KeyBtn = new("TextButton", {Size = UDim2.new(0,70,0,26), Position = UDim2.new(1,-82,0.5,-13), BackgroundColor3 = Color3.fromRGB(30,32,38), Text = key.Name, Font = Enum.Font.Gotham, TextSize = 13, TextColor3 = Theme.TextColor, AutoButtonColor = false, Parent = H})
            new("UICorner", {CornerRadius = UDim.new(0,4), Parent = KeyBtn})
            KeyBtn.MouseButton1Click:Connect(function()
                listening = true
                KeyBtn.Text = "..."
            end)
            UserInputService.InputBegan:Connect(function(input, gpe)
                if listening and input.UserInputType == Enum.UserInputType.Keyboard then
                    key = input.KeyCode
                    KeyBtn.Text = key.Name
                    listening = false
                elseif not gpe and input.KeyCode == key then
                    if callback then callback() end
                end
            end)
        end

        return Tab
    end

    return Window
end

return Paradise