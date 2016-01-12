require 'config'
gauth = require 'gauth'

headers = ngx.req.get_headers();

function get_user()
    local header =  headers['Authorization']
    if header == nil or header:find(" ") == nil then
        return
    end

    local divider = header:find(' ')
    if header:sub(0, divider-1) ~= 'Basic' then
        return
    end

    local auth = ngx.decode_base64(header:sub(divider+1))
    if auth == nil or auth:find(':') == nil then
        return
    end

    divider = auth:find(':')
    local user = auth:sub(0, divider - 1)
    local pass = auth:sub(divider + 1)

	ngx.log(ngx.INFO, "init success")
    if users[user] and gauth.Check(users[user], pass) then
            return user
    end

    return
end

function set_cookie()
    local ck = require "resty.cookie"
    local cookie, err = ck:new()


    local expires_after = 3600
    local expiration = ngx.time() + expires_after
    local token = expiration .. ":" .. ngx.encode_base64(ngx.hmac_sha1(signature, expiration))

    local ok, err = cookie:set({
        key = "auth", value = token, path = "/",
        --domain = ngx.var.server_name,
        httponly = true,
        --secure = true,
        expires = ngx.cookie_time(expiration), max_age = expires_after
    })
end

local user = get_user()

if user then
    ngx.log(ngx.INFO, 'auth success!' .. user)
    set_cookie()
    ngx.header.content_type = 'text/html'
    ngx.say("<html><head><script>location.reload()</script></head></html>")
else
    ngx.header.content_type = 'text/plain'
    ngx.header.www_authenticate = 'Basic realm=""'
    ngx.status = ngx.HTTP_UNAUTHORIZED
    ngx.say('401 Access Denied')
end
