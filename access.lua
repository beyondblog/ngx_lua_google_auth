require 'config'

local cookie = ngx.var.cookie_auth
local hmac = ""
local timestamp = ""

function getClientIp()
	IP = ngx.req.get_headers()["X-Real-IP"]
	if IP == nil then
		IP  = ngx.var.remote_addr 
	end
	if IP == nil then
		IP  = "unknown"
	end
	return IP
end


function whiteip()
	if next(ip_white_list) ~= nil then
		for _,ip in pairs(ip_white_list) do
			if getClientIp() == ip then
				return true
			end
		end
	end
	return false
end

if whiteip() then
	return
end


if ngx.var.uri == "/auth/" then
	return
end

-- Check that the cookie exists.
if cookie ~= nil and cookie:find(":") ~= nil then -- If there's a cookie, split off the HMAC signature
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
