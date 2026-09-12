import unittest
import std/strutils 
import nim_hash/md4

template checkVector(exp, s: string) =
  check secureHash(s) == parseSecureHash(exp)

block: # "single":
  checkVector("31d6cfe0d16ae931b73c59d7e0c089c0", "")
  checkVector("bde52cb31de33e46245e05fbdbd6fb24", "a")
  checkVector("ec388dd78999dfc7cf4632465693b6bf", "ab")
  checkVector("a448017aaf21d8525fc10ae87aa6729d", "abc")
  checkVector("41decd8f579255c5200f86a4bb3ba740", "abcd")
  checkVector("9803f4a34e8eb14f96adba49064a0c41", "abcde")
  checkVector("804e7f1c2586e50b49ac65db5b645131", "abcdef")
  checkVector("752f4adfe53d1da0241b5bc216d098fc", "abcdefg")
  checkVector("ad9daf8d49d81988590a6f0e745d15dd", "abcdefgh")
  checkVector("1e4e28b05464316b56402b3815ed2dfd", "abcdefghi")
  checkVector("dc959c6f5d6f9e04e4380777cc964b3d", "abcdefghij")
  checkVector("1b5701e265778898ef7de5623bbe7cc0", "Discard medicine more than two years old.")
  checkVector("d7f087e090fe7ad4a01cb59dacc9a572", "He who has a shady past knows that nice guys finish last.")
  checkVector("8d050f55b1cadb9323474564be08a521", "The major problem is with sendmail.  -Mark Horton")
  checkVector("a6b7aa35157e984ef5d9b7f32e5fbb52", "The fugacity of a constituent in a mixture of gases at a given temperature is proportional to its mole fraction.  Lewis-Randall Rule")
  checkVector("75661f0545955f8f9abeeb17845f3fd6", "How can you write a big system without C++?  -Paul Glick")

block: # "streaming":
  var state = newMD4State()
  check MD4SecureHash(state.finalize()) == parseSecureHash("31d6cfe0d16ae931b73c59d7e0c089c0")
  
  var state2 = newMD4State()
  state2.update("abc")
  check MD4SecureHash(state2.finalize()) == parseSecureHash("a448017aaf21d8525fc10ae87aa6729d")
  
  var state3 = newMD4State()
  state3.update("a")
  state3.update("b")
  state3.update("c")
  check MD4SecureHash(state3.finalize()) == parseSecureHash("a448017aaf21d8525fc10ae87aa6729d")

block: # "hash hex":
  var state = newMD4State()
  state.update("abc")
  let hashed = state.finalize()
  check hashed.toString().toHex() == "A448017AAF21D8525FC10AE87AA6729D"

  let hashed2 = secureHash("abc")
  check MD4Digest(hashed2).toString().toHex() == "A448017AAF21D8525FC10AE87AA6729D"

  let hashed3 = secureHash("abc")
  check $hashed3 == "A448017AAF21D8525FC10AE87AA6729D"

block: # "hash file":
  let hashed = secureHashFile("./tests/testdata/testdata.txt")
  check $hashed == "043F8582F241DB351CE627E153E7F0E4"

block: # "hash reset":
  var state = newMD4State()
  state.update("abc")
  let hashed = state.finalize()
  check hashed.toString().toHex() == "A448017AAF21D8525FC10AE87AA6729D"

  state.reset() 
  state.update("abcdefghijklmnopqrstuvwxyz")
  let hashed2 = state.finalize()
  check hashed2.toString().toHex() == "D79E1C308AA5BBCDEEA8ED63DF412DA9"

block: # "isValidHash":
  check not isValidMD4Hash("")
  check not isValidMD4Hash("A448017AAF21D8525FC10AE87AA6729D1")
  check not isValidMD4Hash("A448017AAFG1D8525FC10AE87AA6729D")
  check isValidMD4Hash("A448017AAF21D8525FC10AE87AA6729D")
  check isValidMD4Hash("a448017aaf21d8525fc10ae87aa6729d")
  check isValidMD4Hash("a448017aaf21D8525FC10AE87AA6729D")

  check MD4DigestSize == 16
  check MD4BlockSize == 64
