import unittest
import std/strutils 
import nim_hash/ripemd160

template checkVector(exp, s: string) =
  check secureHash(s) == parseSecureHash(exp)

block: # "single":
  checkVector("9c1185a5c5e9fc54612808977ee8f548b2258d31", "")
  checkVector("0bdc9d2d256b3ee9daae347be6f4dc835a467ffe", "a")
  checkVector("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc", "abc")
  checkVector("5d0689ef49d2fae572b881b123a85ffa21595f36", "message digest")
  checkVector("f71c27109c692c1b56bbdceb5b9d2865b3708dbc", "abcdefghijklmnopqrstuvwxyz")
  checkVector("b0e20b6e3116640286ed3a87a5713079b21f5189", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
  checkVector("9b752e45573d4b39f4dbd3323cab82bf63326bfb", "12345678901234567890123456789012345678901234567890123456789012345678901234567890")

block: # "streaming":
  var state = newRipemd160State()
  check Ripemd160SecureHash(state.finalize()) == parseSecureHash("9c1185a5c5e9fc54612808977ee8f548b2258d31")
  
  var state2 = newRipemd160State()
  state2.update("abc")
  check Ripemd160SecureHash(state2.finalize()) == parseSecureHash("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc")
  
  var state3 = newRipemd160State()
  state3.update("a")
  state3.update("b")
  state3.update("c")
  check Ripemd160SecureHash(state3.finalize()) == parseSecureHash("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc")

block: # "hash hex":
  var state = newRipemd160State()
  state.update("abc")
  let hashed = state.finalize()
  check hashed.toString().toHex() == "8EB208F7E05D987A9B044A8E98C6B087F15A0BFC"

  let hashed2 = secureHash("abc")
  check Ripemd160Digest(hashed2).toString().toHex() == "8EB208F7E05D987A9B044A8E98C6B087F15A0BFC"

  let hashed3 = secureHash("abc")
  check $hashed3 == "8EB208F7E05D987A9B044A8E98C6B087F15A0BFC"

block: # "hash file":
  let hashed = secureHashFile("./tests/testdata/testdata.txt")
  check $hashed == "B0E20B6E3116640286ED3A87A5713079B21F5189"

block: # "hash reset":
  var state = newRipemd160State()
  state.update("abc")
  let hashed = state.finalize()
  check hashed.toString().toHex() == "8EB208F7E05D987A9B044A8E98C6B087F15A0BFC"

  state.reset() 
  state.update("abcdefghijklmnopqrstuvwxyz")
  let hashed2 = state.finalize()
  check hashed2.toString().toHex() == "F71C27109C692C1B56BBDCEB5B9D2865B3708DBC"

block: # "million_a":
  var state = newRipemd160State()
  for i in 0 ..< 100000:
    state.update("aaaaaaaaaa")
  check Ripemd160SecureHash(state.finalize()) == parseSecureHash("52783243c1697bdbe16d37f97f68f08325dc1528")

block: # "isValidHash":
  check not isValidRipemd160Hash("")
  check not isValidRipemd160Hash("8EB208F7E05D987A9B044A8E98C6B087F15A0BFC1")
  check not isValidRipemd160Hash("8EB208F7E05D987A9BG44A8E98C6B087F15A0BFC")
  check isValidRipemd160Hash("8EB208F7E05D987A9B044A8E98C6B087F15A0BFC")
  check isValidRipemd160Hash("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc")
  check isValidRipemd160Hash("8eb208f7E05D987A9B044A8E98C6B087F15A0BFC")

  check Ripemd160DigestSize == 20
  check Ripemd160BlockSize == 64
