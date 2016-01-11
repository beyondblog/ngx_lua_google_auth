local sha1 = require "sha1"
local band = bit32.band

function base32dec(str)
	local b32ab = {
		A=0, B=1, C=2, D=3, E=4, F=5, G=6, H=7, I=8, J=9, K=10, L=11, M=12, N=13,
		O=14, P=15, Q=16, R=17, S=18, T=19, U=20, V=21, W=22, X=23, Y=24, Z=25, 
		a=0, b=1, c=2, d=3, e=4, f=5, g=6, h=7, i=8, j=9, k=10, l=11, m=12, n=13,
		o=14, p=15, q=16, r=17, s=18, t=19, u=20, v=21, w=22, x=23, y=24, z=25,
		[2]=26, [3]=27, [4]=28, [5]=29, [6]=30, [7]=31 }
	local function findab(s, i)
		return b32ab[s:sub(i, i)]
	end
	local function b32halfdec(s, z)
		local a, b = findab(s, z + 1), findab(s, z + 2)
		local c, d = findab(s, z + 3), findab(s, z + 4)
		local e, f = findab(s, z + 5), findab(s, z + 6)
		local g, h = findab(s, z + 7), findab(s, z + 8)
		local i = a * 8 + band(b, 0x1C) / 4
		local j = band(b, 0x3) * 0x40 + c * 2 + band(d, 0x10) / 0x10
		local k = band(d, 0xF) * 0x10 + band(e, 0x1E) / 2
		local l = band(e, 1) * 0x80 + f * 4 + band(g, 0x18) / 0x10
		local m = band(g, 7) * 0x20 + h
		return string.char(i, j, k, l, m)
	end
	return b32halfdec(str, 0) .. b32halfdec(str, 8)
end

local GAuth = {}

function GAuth.GenCode(skey, value)
	value = string.char(
		0, 0, 0, 0,
		band(value, 0xFF000000) / 0x1000000,
		band(value, 0xFF0000) / 0x10000,
		band(value, 0xFF00) / 0x100,
		band(value, 0xFF))
	local hash = sha1.hmac_binary(skey, value)
	local offset = band(hash:sub(-1):byte(1, 1), 0xF)
	local function bytesToInt(a,b,c,d)
		return a*0x1000000 + b*0x10000 + c*0x100 + d
	end
	hash = bytesToInt(hash:byte(offset + 1, offset + 4))
	hash = band(hash, 0x7FFFFFFF) % 1000000
	return ("%06d"):format(hash)
end

function GAuth.Check(skey, value)
	local base = math.floor(os.time() / 30)
	skey = base32dec(skey)
	if GAuth.GenCode(skey, base) == value then return true end
	if GAuth.GenCode(skey, base - 1) == value then return true end
	if GAuth.GenCode(skey, base + 1) == value then return true end
	return false
end

return GAuth