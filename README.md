## NIM-hash 

A hash library for nim.


### Env

 - nim >= 2.2.10


### Adding nim-hash as a dependency

Add the dependency to your project:

```bash
nimble install nim_hash
```

or 

```bash
nimble install https://github.com/deatil/nim-hash
```

The `nim-hash` structure can be imported in your application with:

```nim
import nim_hash/sm3
```


### Get Starting

~~~nim
import std/strutils
import nim_hash/sm3

when isMainModule:
  var state = newSM3State()
  state.update("abc")
  let hashed = state.finalize()

  var s = newStringOfCap(hashed.len)
  for b in hashed:
    s.add(char(b))

  // output: 66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0
  echo("output: ", s)
~~~

### Hash Functions

 - `sm3`: nim_hash/sm3


### LICENSE

*  The library LICENSE is `Apache2`, using the library need keep the LICENSE.


### Copyright

*  Copyright deatil(https://github.com/deatil).
