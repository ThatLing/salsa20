# salsa20
GLua implementation of Salsa20

## Usage

```
local key = string.rep("a", 32)
local nonce = tostring(os.time()):sub(1, 8)
local plainText = string.rep("b", 512)

local cipherText = salsa20.crypt(key, nonce, plainText, 20)

local decryptedText = salsa20.crypt(key, nonce, cipherText, 20)
```

Full specifications can be found [here](https://cr.yp.to/snuffle/spec.pdf).
