function readPcap(buf, callback) {
  var bp  = new BinaryParser(buf)

  var magic        = bp.read('u32'),
      tsMultiplier = 1000
  switch (magic) {
    case 0xa1b2c3d4:                    break
    case 0xd4c3b2a1: bp.flipped = true; break
    case 0xa1b23c4d:                    tsMultiplier = 1; break
    case 0x4d3cb2a1: bp.flipped = true; tsMultiplier = 1; break
    default:
      throw new Error("Bad magic number for pcap file: " + magic.toString(16))
  }

  var header = bp.read([ { version_major: 'u16' },
                         { version_minor: 'u16' },
                         { thiszone:      'i32' },
                         { sigfigs:       'u32' },
                         { snaplen:       'u32' },
                         { network:       'u32' } ])
  header.tsMultiplier = tsMultiplier

  while (!bp.isEOF()) {
    var recHeader = bp.read([ { ts_sec:   'u32' },
                              { ts_usec:  'u32' },
                              { incl_len: 'u32' },
                              { orig_len: 'u32' } ]),
        record    = bp.read('buf[' + recHeader.incl_len + ']')
    callback(null, header, recHeader, record)
  }
}

if (typeof exports == 'object') {
  var BinaryParser = require('./binaryparser').BinaryParser
  exports.read = readPcap
}
