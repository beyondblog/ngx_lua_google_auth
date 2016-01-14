# ngx_lua_google_auth
simple google authentication for nginx by lua

## How to use

###Synopsis
```
modify nginx.conf file
...
http {
...

      lua_package_path '/usr/local/lualib/?.lua;/YOU_PATH/conf/ngx_lua_google_auth/?.lua;';
      init_by_lua_file  /YOU_PATH/conf/ngx_lua_google_auth/init.lua;
      
...
}
...

server {

      access_by_lua_file '/YOU_PATH/conf/ngx_lua_google_auth/access.lua';
      
...
}
...

```
### config

```
edit /YOU_PATH/conf/ngx_lua_google_auth/config.lua

-- auth router
auth_url = "/auth/"

-- ip white list
ip_white_list = {"10.10.1.1"}

-- signature
signature = "ngx_lua_google_auth"

-- user list
users = {}
users["beyondblog"] = "BHSOTR7UKYQWU5NJ" 

-- `beyondblog`  is auth users , key is the value.
-- `BHSOTR7UKYQWU5NJ` is google authenticator secret

```

```
$ nginx -t
$ nginx -s reload
```


## Reference

[0] [Writing an nginx authentication module in Lua](http://www.stavros.io/posts/writing-an-nginx-authentication-module-in-lua/)

[1] [imzyxwvu/lua-gauth](http://github.com/imzyxwvu/lua-gauth/)

[2] https://github.com/google/google-authenticator

## License
The MIT License (MIT)

Copyright (c) 2016 Richard Yang

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
