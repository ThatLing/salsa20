
salsa20 = {}

local error = error
local string_byte = string.byte
local string_char = string.char
local string_len = string.len
local string_format = string.format
local bit_bxor = bit.bxor
local bit_rol = bit.rol
local bit_ror = bit.ror
local bit_band = bit.band
local table_concat = table.concat
local table_remove = table.remove
local table_Copy = table.Copy
local math_floor = math.floor

local function quarterround(t, x, y, z, w)
	t[y] = bit_bxor(t[y], bit_rol(t[x] + t[w], 7))
	t[z] = bit_bxor(t[z], bit_rol(t[y] + t[x], 9))
	t[w] = bit_bxor(t[w], bit_rol(t[z] + t[y], 13))
	t[x] = bit_bxor(t[x], bit_rol(t[w] + t[z], 18))
end
salsa20.quarterround = quarterround

local function rowround(x)
	quarterround(x, 1, 	2,	3,	4)
	quarterround(x, 6, 	7,	8,	5)
	quarterround(x, 11, 12,	9,	10)
	quarterround(x, 16, 13,	14,	15)
end
salsa20.rowround = rowround

local function columnround(x)
	quarterround(x, 1, 	5, 	9, 	13)
	quarterround(x, 6, 	10, 14, 2)
	quarterround(x, 11, 15, 3, 	7)
	quarterround(x, 16, 4,	8, 	12)
end
salsa20.columnround = columnround

local function doubleround(x)
	columnround(x)
	rowround(x)
end
salsa20.doubleround = doubleround

local function littleendian(b)
	return 		b[1] 		+ 
		bit_rol(b[2], 8)  	+ 
		bit_rol(b[3], 16) 	+ 
		bit_rol(b[4], 24)
end
salsa20.littleendian = littleendian

local function inv_littleendian(b)
	local x0 = bit_band(		b, 			0xFF)
	local x1 = bit_band(bit_ror(b, 8 ), 	0xFF)
	local x2 = bit_band(bit_ror(b, 16), 	0xFF)
	local x3 = bit_band(bit_ror(b, 24), 	0xFF)
	
	return x0, x1, x2, x3
end
salsa20.inv_littleendian = inv_littleendian

local function hash(b, rounds)
	local x = {}
	local out = {}
	
	for i = 1, 64, 4 do
		x[#x + 1] = ChaCha.littleendian({b[i], b[i + 1], b[i + 2], b[i + 3]}) 
	end
	
	
	local z = table_Copy(x)
	for i = 1, rounds / 2 do
		doubleround(z)
	end
	
	for i = 1, 16 do
		local p = (i * 4) - 3
		out[p], out[p + 1], out[p + 2], out[p + 3] = inv_littleendian(z[i] + x[i])
	end
	
	return out
end
salsa20.hash = hash

local t
local function expand(k, n, rounds)
	local out = {}
	local keyLen = #k
	local is32Byte = keyLen == 32
	if not t then
		t = { string_byte(string_format("expand %d-byte k", keyLen), 1, -1) }
	end
	
	for i = 1, 64, 20 do
		for j = 1, 4 do
			out[(i - 1) + j] = t[math_floor(i / 20) * 4 + j]		-- This is ugly
		end
	end
	
	for i = 1, 16 do
		out[i + 4] = k[i]
		out[i + 24] = n[i]
		
		if is32Byte then
			out[i + 44] = k[i + 16]
		else
			out[i + 44] = k[i]
		end
	end
	
	return hash(out, rounds)
end
salsa20.expand = expand

local function makekey(k, v, i, j, rounds)
	local n = {}
	
	if (j / 64) > 1 then
		local p = 1
		local b
		
		for k = 1, 8 do
			b = bit_band(i[k] + p, 0xFF)
			p = math_floor((i[k] + p) / 0xFF)
			i[k] = b
			
			if p == 0 then
				break
			end
		end
	end
	
	for k = 1, 8 do
		n[k] 	 = v[k]
		n[k + 8] = i[k]
	end
	
	return expand(k, n, rounds), i
end
salsa20.makekey = makekey

local function crypt(k, v, m, rounds)
	if #k ~= 32 and #k ~= 16 then
		error("salsa20.crypt: k must be 16 or 32 bytes in size; got " .. #k)
	end
	
	if #v ~= 8 then
		error("salsa20.crypt: v must be 8 bytes in size; got " .. #v)
	end
	
	if rounds ~= 20 and rounds ~= 12 and rounds ~= 8 then
		error("salsa20.crypt: rounds must be 20, 12 or 8; got " .. tostring(rounds))
	end
	
	
	local ciphertext = {}
	local i = {0, 0, 0, 0, 0, 0, 0, 0}
	local key = {}
	t = nil
	
	k = { string_byte(k, 1, -1) }
	v = { string_byte(v, 1, -1) }
	
	for j = 1, string_len(m) do
		if #key == 0 then
			key, i = makekey(k, v, i, j, rounds)
		end
		
		ciphertext[j] = string_char(bit_bxor(string_byte(m, j), key[1]))
		table_remove(key, 1)
	end
	
	return table_concat(ciphertext)
end
salsa20.crypt = crypt
