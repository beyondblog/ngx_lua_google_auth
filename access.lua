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

function whiteHost()
	if next(host_white_list) ~= nil then
		for _, host in pairs(host_white_list) do
			if ngx.var.host ==  host then
				return true
			end
		end
	end
	return false
end

if whiteHost() then
	return
end

if ngx.var.uri == auth_url then
	if authorization() then
		return
	end
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
-- /auth_url/ if there's no valid token.
ngx.exec(auth_url)
