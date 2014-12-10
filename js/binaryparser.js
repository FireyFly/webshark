var StandardTypes = { u8:  [ 1,   'Uint8' ],
                      u16: [ 2,  'Uint16' ],
                      u32: [ 4,  'Uint32' ],
                      i8:  [ 1,    'Int8' ],
                      i16: [ 2,   'Int16' ],
                      i32: [ 4,   'Int32' ],
                      f32: [ 4, 'Float32' ],
                      f64: [ 8, 'Float64' ] }

function BinaryParser(buf, types) {
  this.buffer  = buf
  this.view    = new DataView(buf)
  this.types   = types || {}
  this.cursor  = 0
  this.flipped = false
}

BinaryParser.prototype.isEOF = function () {
  return this.cursor >= this.buffer.byteLength
}

BinaryParser.prototype.read = function (type) {
  var self = this

  if (type.slice(0,4) == 'buf[') {
    var countS = type.slice(4,-1),
        count  = countS == '*'? this.buffer.byteLength - this.cursor
               :                parseInt(countS),
        res    = this.buffer.slice(this.cursor, this.cursor + count)
    this.cursor += count
    return res

  } else if (type in this.types) {
    var pair = this.types[type](this.cursor, this.buffer, this.view),
        len  = pair[0],
        res  = pair[1]
    this.cursor += len
    return res

  } else if (type in StandardTypes) {
    var len  = StandardTypes[type][0],
        name = StandardTypes[type][1]

    var res  = this.view['get' + name](this.cursor, this.flipped)
    this.cursor += len
    return res

  } else if (Array.isArray(type)) {
    var res = {}
    type.forEach(function (kv) {
      kv = extractKV(kv)
      var key   = kv[0],
          type  = kv[1]
      res[key] = self.read(type)
    })
    return res
  }

  function extractKV(obj) {
    if ('0' in obj && '1' in obj) {
      return [ obj[0], obj[1] ]

    } else {
      for (var key in obj) {
        return [ key, obj[key] ]
      }
    }
    throw new Error("No key-value pair found!")
  }
}


if (typeof exports == 'object') {
  exports.BinaryParser = BinaryParser
}


//-- Testing ----------------------------------------------
/*
function readFileSync(name) {
  var fs = require('fs')

  var buf  = fs.readFileSync(name),
      abuf = new ArrayBuffer(buf.length),
      u8   = new Uint8Array(abuf)
  for (var i = 0; i < buf.length; i++) u8[i] = buf[i]

  return abuf
}

var pcap = require('./pcap')

var buf = readFileSync('data/sample-1.pcap')
pcap.read(buf, function (err, header, recHeader, record) {
  if (err) throw err
  console.log(recHeader)
  console.log(record.byteLength)
})
//*/
