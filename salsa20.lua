
salsa20 = {}

local string_byte = string.byte
local string_char = string.char
local string_len = string.len
local string_format = string.format
local bit_bxor = bit.bxor
local bit_rol = bit.rol
local bit_ror = bit.ror
local bit_band = bit.band
local table_concat = table.concat
local table_Copy = table.Copy
local math_floor = math.floor

function salsa20.quarterround(y0, y1, y2, y3)
	local z1 = bit_bxor(y1, bit_rol(y0 + y3, 7))
	local z2 = bit_bxor(y2, bit_rol(z1 + y0, 9))
	local z3 = bit_bxor(y3, bit_rol(z2 + z1, 13))
	local z0 = bit_bxor(y0, bit_rol(z3 + z2, 18))
	
	return z0, z1, z2, z3
end

function salsa20.rowround(y)
	local z = {}
	
	z[1],	z[2],	z[3],	z[4]  = salsa20.quarterround(y[1], 	y[2],	y[3],	y[4])
	z[6],	z[7],	z[8],	z[5]  = salsa20.quarterround(y[6], 	y[7],	y[8],	y[5])
	z[11],	z[12],	z[9],	z[10] = salsa20.quarterround(y[11], y[12],	y[9],	y[10])
	z[16],	z[13],	z[14],	z[15] = salsa20.quarterround(y[16], y[13],	y[14],	y[15])
	
	return z
end

function salsa20.columnround(x)
	local y = {}
	
	y[1], 	y[5], 	y[9], 	y[13] = salsa20.quarterround(x[1], 	x[5], 	x[9], 	x[13])
	y[6], 	y[10], 	y[14], 	y[2]  = salsa20.quarterround(x[6], 	x[10], 	x[14], 	x[2])
	y[11], 	y[15], 	y[3], 	y[7]  = salsa20.quarterround(x[11], x[15], 	x[3], 	x[7])
	y[16], 	y[4],	y[8], 	y[12] = salsa20.quarterround(x[16], x[4],	x[8], 	x[12])
	
	return y
end

function salsa20.doubleround(x)
	return salsa20.rowround(salsa20.columnround(x))
end

function salsa20.littleendian(b)
	if #b ~= 4 then
		debug.Trace()
		error("salsa20.littleendian: b must be 4 bytes in size; got " .. #b)
	end
	
	return b[1] + b[2] * (2 ^ 8) + b[3] * (2 ^ 16) + b[4] * (2 ^ 24)
end

function salsa20.inv_littleendian(b)
	x0 = bit_band(		  b, 		0xFF)
	x1 = bit_band(bit_ror(b, 8), 	0xFF)
	x2 = bit_band(bit_ror(b, 16), 	0xFF)
	x3 = bit_band(bit_ror(b, 24), 	0xFF)
	
	return x0, x1, x2, x3
end

function salsa20.hash(b, rounds)
	if #b ~= 64 then
		error("salsa20.hash: b must be 64 bytes in size; got " .. #b)
	end
	
	local x = {}
	local out = {}
	
	for i = 1, 16 do
		local p = (i * 4) - 3
		x[i] = salsa20.littleendian({b[p], b[p + 1], b[p + 2], b[p + 3]}) 
	end
	
	
	local z = table_Copy(x)
	for i = 1, rounds / 2 do
		z = salsa20.doubleround(z)
	end
	
	for i = 1, 16 do
		local p = (i * 4) - 3
		out[p], out[p + 1], out[p + 2], out[p + 3] = salsa20.inv_littleendian(z[i] + x[i])
	end
	
	return out
end

function salsa20.expand(k, n, rounds)
	if #k ~= 16 and #k ~= 32 then
		error("salsa20.expand: k must be 16 or 32 bytes in size; got " .. #k)
	end
	
	if #n ~= 16 then
		error("salsa20.expand: n must be 16 bytes in size; got " .. #n)
	end
	
	local out = {}
	local t = { string_byte(string_format("expand %d-byte k", #k), 1, -1) }
	local is32Byte = #k == 32
	
	for i = 1, 64, 20 do
		for j = 1, 4 do
			out[(i - 1) + j] = t[math_floor(i / 20) * 4 + j]
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
	
	return salsa20.hash(out, rounds)
end

function salsa20.makekey(k, v, i, j, rounds)
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
	
	return salsa20.expand(k, n, rounds), i
end

function salsa20.crypt(k, v, m, rounds)
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
	
	k = { string_byte(k, 1, -1) }
	v = { string_byte(v, 1, -1) }
	
	for j = 1, string_len(m) do
		if j % 64 == 1 then
			key, i = salsa20.makekey(k, v, i, j, rounds)
		end
		
		ciphertext[j] = string_char(bit_bxor(string_byte(m, j), key[((j - 1) % 64) + 1]))
	end
	
	return table_concat(ciphertext)
end

