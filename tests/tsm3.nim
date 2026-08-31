import unittest
import std/assertions
import std/strutils 
import nim_hash/sm3

test "rotl32":
  check rotl32(15, 5) == 480
  check p0(6) == 789510
  check p1(3) == 25264131
  check ff(3, 1, 2) == 3
  check gg(3, 1, 6) == 5

template checkVector(exp, s: string) =
  doAssert secureSM3Hash(s) == parseSecureSM3Hash(exp)

test "single":
  checkVector("1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b", "")
  checkVector("623476ac18f65a2909e43c7fec61b49c7e764a91a18ccb82f1917a29c86c5e88", "a")
  checkVector("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0", "abc")
  checkVector("c522a942e89bd80d97dd666e7a5531b36188c9817149e9b258dfe51ece98ed77", "message digest")
  checkVector("b80fe97a4da24afc277564f66a359ef440462ad28dcc6d63adb24d5c20a61595", "abcdefghijklmnopqrstuvwxyz")
  checkVector("2971d10c8842b70c979e55063480c50bacffd90e98e2e60d2512ab8abfdfcec5", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
  checkVector("ad81805321f3e69d251235bf886a564844873b56dd7dde400f055b7dde39307a", "12345678901234567890123456789012345678901234567890123456789012345678901234567890")

test "streaming":
  var state = newSM3State()
  doAssert SecureSM3Hash(state.finalize()) == parseSecureSM3Hash("1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b")
  
  var state2 = newSM3State()
  state2.update("abc")
  doAssert SecureSM3Hash(state2.finalize()) == parseSecureSM3Hash("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0")
  
  var state3 = newSM3State()
  state3.update("a")
  state3.update("b")
  state3.update("c")
  doAssert SecureSM3Hash(state3.finalize()) == parseSecureSM3Hash("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0")

test "hash hex":
  var state = newSM3State()
  state.update("abc")
  let hashed = state.finalize()

  var s = newStringOfCap(hashed.len)
  for b in hashed:
    s.add(char(b))
  check s.toHex() == "66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0"

test "isValidSM3Hash":
  doAssert not isValidSM3Hash("")
  doAssert not isValidSM3Hash("66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E01")
  doAssert not isValidSM3Hash("66C7F0F462EEGDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0")
  doAssert isValidSM3Hash("66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0")
  doAssert isValidSM3Hash("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0")
  doAssert isValidSM3Hash("66c7f0f462eeedd9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0")
