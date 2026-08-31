import strutils
from endians import bigEndian32

when defined(nimPreviewSlimSystem):
  import std/syncio

const SM3DigestSize = 32
const SM3BlockSize = 64

type
  SM3Digest* = array[0 .. SM3DigestSize - 1, uint8]
  SecureSM3Hash* = distinct SM3Digest

type
  SM3State* = object
    count:   int
    state:   array[8, uint32]
    buf:     array[64, byte]
    buf_len: int

proc newSM3State*(): SM3State =
  result.count = 0
  result.state[0] = 0x7380166f'u32
  result.state[1] = 0x4914b2b9'u32
  result.state[2] = 0x172442d7'u32
  result.state[3] = 0xda8a0600'u32
  result.state[4] = 0xa96f30bc'u32
  result.state[5] = 0x163138aa'u32
  result.state[6] = 0xe38dee4d'u32
  result.state[7] = 0xb0fb0e4e'u32

const 
  sbox: array[64, uint32] = [
    0x79cc4519'u32, 0xf3988a32'u32, 0xe7311465'u32, 0xce6228cb'u32, 0x9cc45197'u32, 0x3988a32f'u32, 0x7311465e'u32, 0xe6228cbc'u32,
    0xcc451979'u32, 0x988a32f3'u32, 0x311465e7'u32, 0x6228cbce'u32, 0xc451979c'u32, 0x88a32f39'u32, 0x11465e73'u32, 0x228cbce6'u32,
    0x9d8a7a87'u32, 0x3b14f50f'u32, 0x7629ea1e'u32, 0xec53d43c'u32, 0xd8a7a879'u32, 0xb14f50f3'u32, 0x629ea1e7'u32, 0xc53d43ce'u32,
    0x8a7a879d'u32, 0x14f50f3b'u32, 0x29ea1e76'u32, 0x53d43cec'u32, 0xa7a879d8'u32, 0x4f50f3b1'u32, 0x9ea1e762'u32, 0x3d43cec5'u32,
    0x7a879d8a'u32, 0xf50f3b14'u32, 0xea1e7629'u32, 0xd43cec53'u32, 0xa879d8a7'u32, 0x50f3b14f'u32, 0xa1e7629e'u32, 0x43cec53d'u32,
    0x879d8a7a'u32, 0xf3b14f5'u32,  0x1e7629ea'u32, 0x3cec53d4'u32, 0x79d8a7a8'u32, 0xf3b14f50'u32, 0xe7629ea1'u32, 0xcec53d43'u32,
    0x9d8a7a87'u32, 0x3b14f50f'u32, 0x7629ea1e'u32, 0xec53d43c'u32, 0xd8a7a879'u32, 0xb14f50f3'u32, 0x629ea1e7'u32, 0xc53d43ce'u32,
    0x8a7a879d'u32, 0x14f50f3b'u32, 0x29ea1e76'u32, 0x53d43cec'u32, 0xa7a879d8'u32, 0x4f50f3b1'u32, 0x9ea1e762'u32, 0x3d43cec5'u32
  ]

proc rotl32*(x: uint32, n: uint8): uint32 =
  return (x shl n) or (x shr (32'u32 - n))

proc p0*(x: uint32): uint32 =
  return x xor rotl32(x, 9) xor rotl32(x, 17)

proc p1*(x: uint32): uint32 =
  return x xor rotl32(x, 15) xor rotl32(x, 23)

proc ff*(x, y, z: uint32): uint32 =
  return (x and y) or (x and z) or (y and z)

proc gg*(x, y, z: uint32): uint32 =
  return ((y xor z) and x) xor z

proc transform(ctx: var SM3State) =
  var a: array[8, uint32]
  var w: array[68, uint32]

  var ss1, ss2, tt1, tt2: uint32
  var i = 0

  while i < 4:
    bigEndian32(addr w[i], addr ctx.buf[i * 4])
    i += 1

  i = 0
  while i < 8:
    a[i] = ctx.state[i]
    i += 1

  i = 0
  while i < 12:
    bigEndian32(addr w[i + 4], addr ctx.buf[(i + 4) * 4])

    tt2 = rotl32(a[0], 12)
    ss1 = rotl32(tt2 + a[4] + sbox[i], 7)
    ss2 = ss1 xor tt2
    tt1 = (a[0] xor a[1] xor a[2]) + a[3] + ss2 + (w[i] xor w[i + 4])
    tt2 = (a[4] xor a[5] xor a[6]) + a[7] + ss1 + w[i]

    a[3] = a[2]
    a[2] = rotl32(a[1], 9)
    a[1] = a[0]
    a[0] = tt1
    a[7] = a[6]
    a[6] = rotl32(a[5], 19)
    a[5] = a[4]
    a[4] = p0(tt2)

    i += 1

  i = 12
  while i < 16:
    w[i + 4] = p1(w[i - 12] xor w[i - 5] xor rotl32(w[i + 1], 15)) xor rotl32(w[i - 9], 7) xor w[i - 2]
    tt2 = rotl32(a[0], 12)
    ss1 = rotl32(tt2 + a[4] + sbox[i], 7)
    ss2 = ss1 xor tt2
    tt1 = (a[0] xor a[1] xor a[2]) + a[3] + ss2 + (w[i] xor w[i + 4])
    tt2 = (a[4] xor a[5] xor a[6]) + a[7] + ss1 + w[i]

    a[3] = a[2]
    a[2] = rotl32(a[1], 9)
    a[1] = a[0]
    a[0] = tt1
    a[7] = a[6]
    a[6] = rotl32(a[5], 19)
    a[5] = a[4]
    a[4] = p0(tt2)

    i += 1

  i = 16
  while i < 64:
    w[i + 4] = p1(w[i - 12] xor w[i - 5] xor rotl32(w[i + 1], 15)) xor rotl32(w[i - 9], 7) xor w[i - 2]
    tt2 = rotl32(a[0], 12)
    ss1 = rotl32(tt2 + a[4] + sbox[i], 7)
    ss2 = ss1 xor tt2
    tt1 = ff(a[0], a[1], a[2]) + a[3] + ss2 + (w[i] xor w[i + 4])
    tt2 = gg(a[4], a[5], a[6]) + a[7] + ss1 + w[i]

    a[3] = a[2]
    a[2] = rotl32(a[1], 9)
    a[1] = a[0]
    a[0] = tt1
    a[7] = a[6]
    a[6] = rotl32(a[5], 19)
    a[5] = a[4]
    a[4] = p0(tt2)

    i += 1

  i = 0
  while i < 8:
    ctx.state[i] = ctx.state[i] xor a[i]
    i += 1

proc update*(ctx: var SM3State, data: openArray[char]) =
  var i = ctx.buf_len
  var j = 0
  var len = data.len

  if len > 64 - i:
    copyMem(addr ctx.buf[i], unsafeAddr data[j], 64 - i)
    len -= 64 - i
    j += 64 - i
    transform(ctx)
    i = 0

  while len >= 64:
    copyMem(addr ctx.buf[0], unsafeAddr data[j], 64)
    len -= 64
    j += 64
    transform(ctx)

  while len > 0:
    dec len
    ctx.buf[i] = byte(data[j])
    inc i
    inc j
    if i == 64:
      transform(ctx)
      i = 0
  ctx.count += data.len
  ctx.buf_len = i

proc finalize*(ctx: var SM3State): SM3Digest =
  ctx.buf[ctx.buf_len] = 0x80

  for i in (ctx.buf_len + 1) ..< 64:
    ctx.buf[i] = 0x00

  if 64 - ctx.buf_len < 9:
    transform(ctx)
    for i in 0 ..< 64:
      ctx.buf[i] = 0x00

  var bcount = uint64(ctx.count / 64)

  var bcount1 = uint32(bcount shr 23)
  var bcount2 = uint32((bcount shl 9) + (uint64(ctx.buf_len) shl 3))

  bigEndian32(addr ctx.buf[56], addr bcount1)
  bigEndian32(addr ctx.buf[60], addr bcount2)

  transform(ctx)

  for i in 0 ..< 8:
    bigEndian32(addr ctx.state[i], addr ctx.state[i])

  copyMem(addr result[0], addr ctx.state[0], SM3DigestSize)

proc secureSM3Hash*(str: openArray[char]): SecureSM3Hash =
  var state = newSM3State()
  state.update(str)
  SecureSM3Hash(state.finalize())

proc parseSecureSM3Hash*(hash: string): SecureSM3Hash =
  for i in 0 ..< SM3DigestSize:
    SM3Digest(result)[i] = uint8(parseHexInt(hash[i*2] & hash[i*2 + 1]))

proc `==`*(a, b: SecureSM3Hash): bool =
  SM3Digest(a) == SM3Digest(b)

proc isValidSM3Hash*(s: string): bool =
  s.len == 64 and allCharsInSet(s, HexDigits)
