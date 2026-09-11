import strutils

when defined(nimPreviewSlimSystem):
  import std/syncio

const MD2DigestSize* = 16
const MD2BlockSize* = 16

const 
  sbox: array[256, uint8] = [
    uint8 41,  46,  67,  201, 162, 216, 124, 1,   61,  54,  84,  161, 236, 240, 6,
    19,  98,  167, 5,   243, 192, 199, 115, 140, 152, 147, 43,  217, 188, 76,
    130, 202, 30,  155, 87,  60,  253, 212, 224, 22,  103, 66,  111, 24,  138,
    23,  229, 18,  190, 78,  196, 214, 218, 158, 222, 73,  160, 251, 245, 142,
    187, 47,  238, 122, 169, 104, 121, 145, 21,  178, 7,   63,  148, 194, 16,
    137, 11,  34,  95,  33,  128, 127, 93,  154, 90,  144, 50,  39,  53,  62,
    204, 231, 191, 247, 151, 3,   255, 25,  48,  179, 72,  165, 181, 209, 215,
    94,  146, 42,  172, 86,  170, 198, 79,  184, 56,  210, 150, 164, 125, 182,
    118, 252, 107, 226, 156, 116, 4,   241, 69,  157, 112, 89,  100, 113, 135,
    32,  134, 91,  207, 101, 230, 45,  168, 2,   27,  96,  37,  173, 174, 176,
    185, 246, 28,  70,  97,  105, 52,  64,  126, 15,  85,  71,  163, 35,  221,
    81,  175, 58,  195, 92,  249, 206, 186, 197, 234, 38,  44,  83,  13,  110,
    133, 40,  132, 9,   211, 223, 205, 244, 65,  129, 77,  82,  106, 220, 55,
    200, 108, 193, 171, 250, 36,  225, 123, 8,   12,  189, 177, 74,  120, 136,
    149, 139, 227, 99,  232, 109, 233, 203, 213, 254, 59,  0,   29,  57,  242,
    239, 183, 14,  102, 88,  208, 228, 166, 119, 114, 248, 235, 117, 75,  10,
    49,  68,  80,  180, 143, 237, 31,  26,  219, 153, 141, 51,  159, 17,  131,
    20,
  ]


type
  MD2Digest* = array[0 .. MD2DigestSize - 1, uint8]
  MD2SecureHash* = distinct MD2Digest

type
  MD2State* = object
    count:   int
    state:   array[48, uint8]
    buf:     array[16, byte]
    buf_len: int
    digest:  array[16, byte]

proc init(ctx: var MD2State) =
  ctx.count = 0
  ctx.buf_len = 0
  for i in 0 ..< 48:
    ctx.state[i] = 0x00
  for i in 0 ..< 16:
    ctx.digest[i] = 0x00
    
proc newMD2State*(): MD2State =
  init(result)

proc reset*(ctx: var MD2State) =
  init(ctx)

proc transform(ctx: var MD2State, b: array[16, byte]) =
  var t = 0
  var i = 0
  var j = 0

  while i < 16:
    ctx.state[i + 16] = b[i]
    ctx.state[i + 32] = (b[i] xor ctx.state[i]) and 0xff
    i += 1

  i = 0
  while i < 18:
    j = 0
    while j < 48:
      ctx.state[j] = (ctx.state[j] xor sbox[t]) and 0xff
      t = int(ctx.state[j])

      j += 1

    t = (t + i) and 0xff
    i += 1

  t = int(ctx.digest[15])

  i = 0;
  while i < 16:
    ctx.digest[i] = (ctx.digest[i] xor sbox[int(b[i]) xor t]) and 0xff
    t = int(ctx.digest[i])
    i += 1

proc update*(ctx: var MD2State, data: openArray[char]) =
  var i = ctx.buf_len
  var j = 0
  var len = data.len

  if len > 16 - i:
    copyMem(addr ctx.buf[i], unsafeAddr data[j], 16 - i)
    len -= 16 - i
    j += 16 - i
    transform(ctx, ctx.buf)
    i = 0

  while len >= 16:
    copyMem(addr ctx.buf[0], unsafeAddr data[j], 16)
    len -= 16
    j += 16
    transform(ctx, ctx.buf)

  while len > 0:
    dec len
    ctx.buf[i] = byte(data[j])
    inc i
    inc j
    if i == 16:
      transform(ctx, ctx.buf)
      i = 0
  ctx.count += data.len
  ctx.buf_len = i

proc finalize*(ctx: var MD2State): MD2Digest =
  let padding = 16 - ctx.buf_len

  for i in ctx.buf_len ..< 16:
    ctx.buf[i] = byte(padding)

  transform(ctx, ctx.buf)
  transform(ctx, ctx.digest)

  copyMem(addr result[0], addr ctx.state[0], MD2DigestSize)

proc secureHash*(str: openArray[char]): MD2SecureHash =
  var state = newMD2State()
  state.update(str)
  MD2SecureHash(state.finalize())

proc secureHashFile*(filename: string): MD2SecureHash =
  const BufferLength = 8192

  let f = open(filename)
  var state = newMD2State()
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

  MD2SecureHash(state.finalize())

proc `$`*(self: MD2SecureHash): string =
  result = ""
  for v in MD2Digest(self):
    result.add(toHex(int(v), 2))

proc parseSecureHash*(hash: string): MD2SecureHash =
  for i in 0 ..< MD2DigestSize:
    MD2Digest(result)[i] = uint8(parseHexInt(hash[i*2] & hash[i*2 + 1]))

proc `==`*(a, b: MD2SecureHash): bool =
  MD2Digest(a) == MD2Digest(b)

proc isValidMD2Hash*(s: string): bool =
  s.len == 32 and allCharsInSet(s, HexDigits)

proc toString*(dig: MD2Digest): string =
  var s = newStringOfCap(dig.len)
  for b in dig:
    s.add(char(b))

  return s