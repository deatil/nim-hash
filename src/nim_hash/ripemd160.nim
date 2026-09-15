import strutils
from endians import littleEndian32

when defined(nimPreviewSlimSystem):
  import std/syncio

const 
  n1: array[80, uint8] = [
    uint8 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
  ]
  r1: array[80, uint8] = [
    uint8 11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
  ]
  n2: array[80, uint8] = [
    uint8 5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
  ]
  r2: array[80, uint8] = [
    uint8 8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
  ]

  initBox: array[5, uint32] = [
    0x67452301'u32, 0xefcdab89'u32, 0x98badcfe'u32, 0x10325476'u32, 0xc3d2e1f0'u32,
  ]

const Ripemd160DigestSize* = 20
const Ripemd160BlockSize* = 64

type
  Ripemd160Digest* = array[0 .. Ripemd160DigestSize - 1, uint8]
  Ripemd160SecureHash* = distinct Ripemd160Digest

type
  Ripemd160State* = object
    count:   uint64
    state:   array[5, uint32]
    buf:     array[64, byte]
    buf_len: int

proc init(ctx: var Ripemd160State) =
  ctx.count = 0
  ctx.buf_len = 0
  for i in 0 ..< 5:
    ctx.state[i] = initBox[i]

proc newRipemd160State*(): Ripemd160State =
  init(result)

proc reset*(ctx: var Ripemd160State) =
  init(ctx)

proc rotate_left_32(x: uint32, n: int): uint32 {.inline.} =
  return (x shl n) or (x shr (32 - n))

proc bytesToString(bs: seq[byte]): string =
  var s = newStringOfCap(bs.len)
  for b in bs:
    s.add(char(b))

  return s

proc transform(ctx: var Ripemd160State) =
  var x: array[16, uint32]
  var alpha: uint32
  var beta: uint32

  var tmp: uint32

  var a = ctx.state[0]
  var b = ctx.state[1]
  var c = ctx.state[2]
  var d = ctx.state[3]
  var e = ctx.state[4]

  var aa = a
  var bb = b
  var cc = c
  var dd = d
  var ee = e

  var i = 0

  while i < 16:
    littleEndian32(addr x[i], addr ctx.buf[i * 4])
    i += 1

  i = 0
  while i < 16:
    alpha = a + (b xor c xor d) + x[int(n1[i])]
    alpha = rotate_left_32(alpha, int(r1[i])) + e
    beta = rotate_left_32(c, 10)
    a = e
    tmp = b; b = alpha; c = tmp
    tmp = d; d = beta; e = tmp

    alpha = aa + (bb xor (cc or (not dd))) + x[int(n2[i])] + 0x50a28be6'u32
    alpha = rotate_left_32(alpha, int(r2[i])) + ee
    beta = rotate_left_32(cc, 10)
    aa = ee
    tmp = bb; bb = alpha; cc = tmp
    tmp = dd; dd = beta; ee = tmp

    i += 1

  while i < 32:
    alpha = a + ((b and c) or ((not b) and d)) + x[int(n1[i])] + 0x5a827999'u32
    alpha = rotate_left_32(alpha, int(r1[i])) + e
    beta = rotate_left_32(c, 10)
    a = e
    tmp = b; b = alpha; c = tmp
    tmp = d; d = beta; e = tmp

    # parallel line
    alpha = aa + ((bb and dd) or (cc and (not dd))) + x[int(n2[i])] + 0x5c4dd124'u32
    alpha = rotate_left_32(alpha, int(r2[i])) + ee
    beta = rotate_left_32(cc, 10)
    aa = ee
    tmp = bb; bb = alpha; cc = tmp
    tmp = dd; dd = beta; ee = tmp

    i += 1

  while i < 48:
    alpha = a + (b or (not c) xor d) + x[int(n1[i])] + 0x6ed9eba1'u32
    alpha = rotate_left_32(alpha, int(r1[i])) + e
    beta = rotate_left_32(c, 10)
    a = e
    tmp = b; b = alpha; c = tmp
    tmp = d; d = beta; e = tmp

    # parallel line
    alpha = aa + (bb or (not cc) xor dd) + x[int(n2[i])] + 0x6d703ef3'u32
    alpha = rotate_left_32(alpha, int(r2[i])) + ee
    beta = rotate_left_32(cc, 10)
    aa = ee
    tmp = bb; bb = alpha; cc = tmp
    tmp = dd; dd = beta; ee = tmp

    i += 1

  while i < 64:
    alpha = a + ((b and d) or (c and (not d))) + x[int(n1[i])] + 0x8f1bbcdc'u32
    alpha = rotate_left_32(alpha, int(r1[i])) + e
    beta = rotate_left_32(c, 10)
    a = e
    tmp = b; b = alpha; c = tmp
    tmp = d; d = beta; e = tmp

    # parallel line
    alpha = aa + ((bb and cc) or ((not bb) and dd)) + x[int(n2[i])] + 0x7a6d76e9'u32
    alpha = rotate_left_32(alpha, int(r2[i])) + ee
    beta = rotate_left_32(cc, 10)
    aa = ee
    tmp = bb; bb = alpha; cc = tmp
    tmp = dd; dd = beta; ee = tmp

    i += 1

  while i < 80:
    alpha = a + (b xor (c or (not d))) + x[int(n1[i])] + 0xa953fd4e'u32
    alpha = rotate_left_32(alpha, int(r1[i])) + e
    beta = rotate_left_32(c, 10)
    a = e
    tmp = b; b = alpha; c = tmp
    tmp = d; d = beta; e = tmp

    # parallel line
    alpha = aa + (bb xor cc xor dd) + x[int(n2[i])]
    alpha = rotate_left_32(alpha, int(r2[i])) + ee
    beta = rotate_left_32(cc, 10)
    aa = ee
    tmp = bb; bb = alpha; cc = tmp
    tmp = dd; dd = beta; ee = tmp

    i += 1

  dd += c + ctx.state[1]
  ctx.state[1] = ctx.state[2] + d + ee
  ctx.state[2] = ctx.state[3] + e + aa
  ctx.state[3] = ctx.state[4] + a + bb
  ctx.state[4] = ctx.state[0] + b + cc
  ctx.state[0] = dd

proc update*(ctx: var Ripemd160State, data: openArray[char]) =
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

proc finalize*(ctx: var Ripemd160State): Ripemd160Digest =
  var tc = ctx.count

  var tmp: array[64, byte]
  tmp[0] = 0x80
  let rem = tc mod 64
  if rem < 56:
    ctx.update(bytesToString(tmp[0..<(56 - rem)]))
  else:
    ctx.update(bytesToString(tmp[0..<(64 + 56 - rem)]))

  tc = tc shl 3
  for i in 0 ..< 8:
    tmp[i] = byte((tc shr (8 * i)) and 0xFF'u64)

  ctx.update(bytesToString(tmp[0..<8]))
  
  for i in 0 ..< 5:
    littleEndian32(addr ctx.state[i], addr ctx.state[i])

  copyMem(addr result[0], addr ctx.state[0], Ripemd160DigestSize)

proc secureHash*(str: openArray[char]): Ripemd160SecureHash =
  var state = newRipemd160State()
  state.update(str)
  Ripemd160SecureHash(state.finalize())

proc secureHashFile*(filename: string): Ripemd160SecureHash =
  const BufferLength = 8192

  let f = open(filename)
  var state = newRipemd160State()
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

  Ripemd160SecureHash(state.finalize())

proc `$`*(self: Ripemd160SecureHash): string =
  result = ""
  for v in Ripemd160Digest(self):
    result.add(toHex(int(v), 2))

proc parseSecureHash*(hash: string): Ripemd160SecureHash =
  for i in 0 ..< Ripemd160DigestSize:
    Ripemd160Digest(result)[i] = uint8(parseHexInt(hash[i*2] & hash[i*2 + 1]))

proc `==`*(a, b: Ripemd160SecureHash): bool =
  Ripemd160Digest(a) == Ripemd160Digest(b)

proc isValidRipemd160Hash*(s: string): bool =
  s.len == 40 and allCharsInSet(s, HexDigits)

proc toString*(dig: Ripemd160Digest): string =
  var s = newStringOfCap(dig.len)
  for b in dig:
    s.add(char(b))

  return s
