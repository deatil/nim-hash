import unittest
import std/strutils 
import nim_hash/md2

template checkVector(exp, s: string) =
  check secureHash(s) == parseSecureHash(exp)

block: # "single":
  checkVector("8350e5a3e24c153df2275c9f80692773", "")
  checkVector("32ec01ec4a6dac72c0ab96fb34c0b5d1", "a")
  checkVector("da853b0d3f88d99b30283a69e6ded6bb", "abc")
  checkVector("ab4f496bfb2a530b219ff33031fe06b0", "message digest")
  checkVector("4e8ddff3650292ab5a4108c3aa47940b", "abcdefghijklmnopqrstuvwxyz")
  checkVector("da33def2a42df13975352846c30338cd", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
  checkVector("d5976f79d83d3a0dc9806c3c66f3efd8", "12345678901234567890123456789012345678901234567890123456789012345678901234567890")

block: # "streaming":
  var state = newMD2State()
  check MD2SecureHash(state.finalize()) == parseSecureHash("8350e5a3e24c153df2275c9f80692773")
  
  var state2 = newMD2State()
  state2.update("abc")
  check MD2SecureHash(state2.finalize()) == parseSecureHash("da853b0d3f88d99b30283a69e6ded6bb")
  
  var state3 = newMD2State()
  state3.update("a")
  state3.update("b")
  state3.update("c")
  check MD2SecureHash(state3.finalize()) == parseSecureHash("da853b0d3f88d99b30283a69e6ded6bb")

block: # "hash hex":
  var state = newMD2State()
  state.update("abc")
  let hashed = state.finalize()
  check hashed.toString().toHex() == "DA853B0D3F88D99B30283A69E6DED6BB"

  let hashed2 = secureHash("abc")
  check MD2Digest(hashed2).toString().toHex() == "DA853B0D3F88D99B30283A69E6DED6BB"

  let hashed3 = secureHash("abc")
  check $hashed3 == "DA853B0D3F88D99B30283A69E6DED6BB"

block: # "hash file":
  let hashed = secureHashFile("./tests/testdata/testdata.txt")
  check $hashed == "DA33DEF2A42DF13975352846C30338CD"

block: # "hash reset":
  var state = newMD2State()
  state.update("abc")
  let hashed = state.finalize()
  check hashed.toString().toHex() == "DA853B0D3F88D99B30283A69E6DED6BB"

  state.reset() 
  state.update("abcdefghijklmnopqrstuvwxyz")
  let hashed2 = state.finalize()
  check hashed2.toString().toHex() == "4E8DDFF3650292AB5A4108C3AA47940B"

block: # "isValidHash":
  check not isValidMD2Hash("")
  check not isValidMD2Hash("DA853B0D3F88D99B30283A69E6DED6BB1")
  check not isValidMD2Hash("DA853B0D3F88G99B30283A69E6DED6BB")
  check isValidMD2Hash("DA853B0D3F88D99B30283A69E6DED6BB")
  check isValidMD2Hash("da853b0d3f88d99b30283a69e6ded6bb")
  check isValidMD2Hash("da853B0D3F88D99B30283A69E6DED6BB")

  check MD2DigestSize == 16
  check MD2BlockSize == 16
