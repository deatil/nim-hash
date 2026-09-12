import strutils
from endians import littleEndian32

when defined(nimPreviewSlimSystem):
  import std/syncio

const MD4DigestSize* = 16
const MD4BlockSize* = 64

const 
  shift1: array[4, int] = [
    int 3, 7, 11, 19,
  ]
  shift2: array[4, int] = [
    int 3, 5, 9, 13,
  ]
  shift3: array[4, int] = [
    int 3, 9, 11, 15,
  ]

  xIndex2: array[16, int] = [
    int 0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15,
  ]
  xIndex3: array[16, int] = [
    int 0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15,
  ]

  initBox: array[4, uint32] = [
   0x67452301'u32, 0xEFCDAB89'u32, 0x98BADCFE'u32, 0x10325476'u32,
  ]

type
  MD4Digest* = array[0 .. MD4DigestSize - 1, uint8]
  MD4SecureHash* = distinct MD4Digest

type
  MD4State* = object
    count:   uint64
    state:   array[4, uint32]
    buf:     array[64, byte]
    buf_len: int

proc init(ctx: var MD4State) =
  ctx.count = 0
  ctx.buf_len = 0
  for i in 0 ..< 4:
    ctx.state[i] = initBox[i]

proc newMD4State*(): MD4State =
  init(result)

proc reset*(ctx: var MD4State) =
  init(ctx)

proc rotate_left_32(x: uint32, n: int): uint32 {.inline.} =
  return (x shl n) or (x shr (32'u32 - uint32(n)))

proc transform(ctx: var MD4State) =
  var a = ctx.state[0]
  var b = ctx.state[1]
  var c = ctx.state[2]
  var d = ctx.state[3]

  var tmp: uint32

  var x: array[16, uint32]

  var i = 0
  while i < 16:
    littleEndian32(addr x[i], addr ctx.buf[i * 4])
    i += 1

  # Round 1.
  i = 0;
  while i < 16:
    let xn = i
    let s = shift1[i mod 4]
    let f = ((c xor d) and b) xor d

    a = a + f + x[xn]
    a = rotate_left_32(a, s)

    tmp = d
    d = c
    c = b
    b = a
    a = tmp

    i += 1

  # Round 2.
  i = 0;
  while i < 16:
    let xn = xIndex2[i]
    let s = shift2[i mod 4]
    let g = (b and c) or (b and d) or (c and d)

    a = a + g + x[xn] + 0x5a827999
    a = rotate_left_32(a, s)

    tmp = d
    d = c
    c = b
    b = a
    a = tmp

    i += 1

  # Round 3.
  i = 0;
  while i < 16:
    let xn = xIndex3[i]
    let s = shift3[i mod 4]
    let h = b xor c xor d

    a = a + h + x[xn] + 0x6ed9eba1
    a = rotate_left_32(a, s)

    tmp = d
    d = c
    c = b
    b = a
    a = tmp

    i += 1

  ctx.state[0] += a
  ctx.state[1] += b
  ctx.state[2] += c
  ctx.state[3] += d

proc update*(ctx: var MD4State, data: openArray[char]) =
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
  ctx.count += uint64(data.len)
  ctx.buf_len = i

proc finalize*(ctx: var MD4State): MD4Digest =
  ctx.buf[ctx.buf_len] = 0x80

  for i in (ctx.buf_len + 1) ..< 64:
    ctx.buf[i] = 0x00

  if 64 - ctx.buf_len < 9:
    transform(ctx)
    for i in 0 ..< 64:
      ctx.buf[i] = 0x00

  var i = 1
  var len = ctx.count shr 5
  ctx.buf[56] = uint8(ctx.count and 0x1f) shl 3
  while i < 8:
    ctx.buf[56 + i] = uint8(len and 0xff)
    len = len shr 8
    i += 1

  transform(ctx)

  for i in 0 ..< 4:
    littleEndian32(addr ctx.state[i], addr ctx.state[i])

  copyMem(addr result[0], addr ctx.state[0], MD4DigestSize)

proc secureHash*(str: openArray[char]): MD4SecureHash =
  var state = newMD4State()
  state.update(str)
  MD4SecureHash(state.finalize())

proc secureHashFile*(filename: string): MD4SecureHash =
  const BufferLength = 8192

  let f = open(filename)
  var state = newMD4State()
  var buffer = newString(BufferLength)
  while true:
    let length = readChars(f, buffer)
    if length == 0:
      break
    buffer.setLen(length)
    state.update(buffer)
    if length != BufferLength:
      break
  close(f)

  MD4SecureHash(state.finalize())

proc `$`*(self: MD4SecureHash): string =
  result = ""
  for v in MD4Digest(self):
    result.add(toHex(int(v), 2))

proc parseSecureHash*(hash: string): MD4SecureHash =
  for i in 0 ..< MD4DigestSize:
    MD4Digest(result)[i] = uint8(parseHexInt(hash[i*2] & hash[i*2 + 1]))

proc `==`*(a, b: MD4SecureHash): bool =
  MD4Digest(a) == MD4Digest(b)

proc isValidMD4Hash*(s: string): bool =
  s.len == 32 and allCharsInSet(s, HexDigits)

proc toString*(dig: MD4Digest): string =
  var s = newStringOfCap(dig.len)
  for b in dig:
    s.add(char(b))

  return s