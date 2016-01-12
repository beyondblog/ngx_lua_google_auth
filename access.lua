local cookie = ngx.var.cookie_auth
local hmac = ""
local timestamp = ""

function split(s, delim)
    if type(delim) ~= "string" or string.len(delim) <= 0 then
        return
    end

    local start = 1
    local t = {}
    while true do
        local pos = string.find (s, delim, start, true) -- plain find
        if not pos then
            break
        end

        table.insert (t, string.sub (s, start, pos - 1))
        start = pos + string.len (delim)
    end
    table.insert (t, string.sub (s, start))

    return t
end



--ngx.log(ngx.INFO, ip_white_list == nil)
--
--ip_addr = split(ngx.var.remote_addr , ".")
--
--for i = 1, #ip_white_list do
--    if ngx.var.remote_addr == ip_white_list[i] then
--        return
--    end
--    ip_remote_addr = split (ip_white_list[i],".")
--    if ip_remote_addr[1] == ip_addr[1] and
--       ip_remote_addr[2] == ip_addr[2] and
--       ip_remote_addr[3] == ip_addr[3] and
--       ip_remote_addr[4] == ip_addr[4] then
--        return
--    end
--end
--

if ngx.var.uri == "/auth/" then
    return
end

-- Check that the cookie exists.
if cookie ~= nil and cookie:find(":") ~= nil then
    -- If there's a cookie, split off the HMAC signature
    -- and timestamp.
    local divider = cookie:find(":")
    hmac = ngx.decode_base64(cookie:sub(divider+1))
    timestamp = cookie:sub(0, divider-1)
    -- Verify that the signature is valid.
    if ngx.hmac_sha1(signature, timestamp) == hmac and tonumber(timestamp) >= ngx.time() then
        ngx.log (ngx.INFO, 'auth pass   request url:'..ngx.var.uri)
        return
    end
end

-- Internally rewrite the URL so that we serve
-- /auth/ if there's no valid token.
ngx.exec("/auth/")
