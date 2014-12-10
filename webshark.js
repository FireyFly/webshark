
var Types = { 'mac': function (offset, buf, view) {
                       var res = 0
                       for (var i = 0; i < 6; i++) {
                         res = (res << 8) | view.getUint8(offset + i)
                       }
                       return [6, res]
                     }
            }


var ether_header_t = [ { dest:   'mac' },
                       { source: 'mac' },
                       { type:   'u16' } ],

    ipv4_header_t  = [ { version_ihl:            'u8' },
                       { dscp_ecn:               'u8' },
                       { length:                'u16' },
                       { id:                    'u16' },
                       { flags_fragment_offset: 'u16' },
                       { ttl:                    'u8' },
                       { protocol:               'u8' },
                       { checksum:              'u16' },
                       { source:                'u32' },
                       { dest:                  'u32' } ],

    udp_header_t   = [ { source_port:           'u16' },
                       { dest_port:             'u16' },
                       { length:                'u16' },
                       { checksum:              'u16' } ],

    tcp_header_t   = [ { source_port:           'u16' },
                       { dest_port:             'u16' },
                       { sequence:              'u32' },
                       { acknowledge:           'u32' },
                       { flags:                 'u16' },
                       { winsize:               'u16' },
                       { checksum:              'u16' },
                       { urgent:                'u16' } ]



function hexdump(buf, highlight) {
  var u8 = new Uint8Array(buf),
      w  = 8

  if (highlight == null) {
    highlight = {}

  } else if (Array.isArray(highlight)) {
    var highlight_ = {}
    highlight.forEach(function (idx) {
      highlight_[idx] = true
    })
    highlight = highlight_
  }

  var pre = document.createElement('pre')

  for (var i = 0; i < u8.length; i += w) {
    for (var j = 0; j < w; j++) {
      if (i + j >= u8.length) {
        pre.appendChild(document.createTextNode('   '))
      } else {
        var v = u8[i + j]
        var text = document.createTextNode(webshark.sprintf('%02x ', v)),
            el   = document.createElement('span')
        el.classList.add(valueToClass(v))
        if (highlight[i + j]) el.classList.add('highlight')
        el.appendChild(text)
        pre.appendChild(el)
      }
    }

    pre.appendChild(document.createTextNode(' '))

    for (var j = 0; j < w; j++) {
      if (i + j >= u8.length) {
        pre.appendChild(document.createTextNode(' '))
      } else {
        var v = u8[i + j]
        var text = document.createTextNode(isPrintable(v)? String.fromCharCode(v) : '.'),
            el   = document.createElement('span')
        el.classList.add(valueToClass(v))
        if (highlight[i + j]) el.classList.add('highlight')
        el.appendChild(text)
        pre.appendChild(el)
      }
    }

    pre.appendChild(document.createTextNode('\n'))
  }

  return pre

  function isPrintable(v) { return 0x20 <= v && v < 0x7F }
  function valueToClass(v) {
    return 0x00 == v?            'zero'
         : 0x01 <= v && v < 0x20? 'low'
         : 0x20 <= v && v < 0x7F? 'print'
         :                       'high'
  }
}


var webshark = {
  packets: [],
  hosts: {}
}
webshark.sprintf = function (fmt /*...*/) {
  var args = arguments,
      i    = 1

  return fmt.replace(/%(-?)(0?)(\d+|)([sbdxfj]|ip|mac)/g, function (_, align, padChar, padN, spec) {
    var str = toString(args[i++], spec),
        pad = Array(Math.max(padN - str.length + 1, 0)).join(padChar || ' ')
    return align != '-'? pad + str : str + pad
  })

  function toString(value, spec) {
    var int = Math.floor(Number(value))
    switch (spec) {
      case 's':   return String(value)
      case 'd':   return String(int)
      case 'x':   return int.toString(16)
      case 'b':   return int.toString(2)
      case 'f':   return Number(value).toFixed(4)
      case 'j':   return JSON.stringify(value)
      case 'ip':  return [ (value >> 24) & 0xFF,
                           (value >> 16) & 0xFF,
                           (value >>  8) & 0xFF,
                           (value >>  0) & 0xFF ].join(".")
      case 'mac': return [ (value >> 36) & 0xFF,
                           (value >> 32) & 0xFF,
                           (value >> 24) & 0xFF,
                           (value >> 16) & 0xFF,
                           (value >>  8) & 0xFF,
                           (value >>  0) & 0xFF ].map(pad2hex).join(":")
      default:
        throw new Error("sprintf: unimplemented spec: '" + spec + "'.")
    }

    function pad2hex(n) {
      return (n < 16? '0' : '') + n.toString(16)
    }
  }
}
webshark.printf = function (/*...*/) {
  console.log(webshark.sprintf.apply(webshark, arguments))
}

webshark.getHost = function () {
  var res = {},
      key = []
  for (var i = 0; i < arguments.length; i += 2) {
    var spec  = arguments[i],
        value = arguments[i + 1]
    res[spec] = value
    key.push(spec + "=" + value)
  }
  key = key.join("_")

  res.key = key
  if (this.hosts[key] == null) this.hosts[key] = res
  return this.hosts[key]
}

/*
webshark.registerPacket = function (packet) {
  this.packets.byTime.push(packet)

  var bySource  = this.packets.bySource,
      byDest    = this.packets.byDest,
      sourceKey = packet.source.key,
      destKey   = packet.dest.key

  if (bySource[sourceKey] == null) bySource[sourceKey] = []
  bySource[sourceKey].push(packet)

  if (byDest[destKey] == null) byDest[destKey] = []
  byDest[destKey].push(packet)
}
*/

webshark.begin = function (header) {
}
webshark.feed = function (recHeader, record) {
  var bp = new BinaryParser(record, Types)

  var etherHeader = bp.read(ether_header_t)
  switch (etherHeader.type) {
    case 0x0800:
      var ipv4Header = bp.read(ipv4_header_t)

      var source = this.getHost('eth',  etherHeader.source,
                                'ipv4', ipv4Header.source),
          dest   = this.getHost('eth',   etherHeader.dest,
                                'ipv4', ipv4Header.dest)

      var packet = { spec:    'ipv4',
                     time:    { sec:  recHeader.ts_sec,
                                usec: recHeader.ts_usec },
                     source:  source,
                     dest:    dest,
                     header:  ipv4Header }

      switch (ipv4Header.protocol) {
        case 0x11:
          var udpHeader = bp.read(udp_header_t)
          packet.udpHeader = udpHeader
          packet.payload = bp.read('buf[' + (udpHeader.length - 8) + ']')
          break;

        case 0x06:
          var tcpHeader = bp.read(tcp_header_t)
          tcpHeader.dataOffset = tcpHeader.flags >> 12
          tcpHeader.options = bp.read('buf[' + 4*(tcpHeader.dataOffset - 5) + ']')
          packet.tcpHeader = tcpHeader
          packet.payload = bp.read('buf[*]')
          break;

        default:
          packet.payload = bp.read('buf[*]')
      }

      this.packets.push(packet)
      break

    default:
      console.warn("Skipping non-IPv4 packet...")
  }
}
webshark.end = function () {
  var commsMap = {},
      rows     = []

  var t0 = this.packets[0].time.sec

  this.packets.forEach(function (packet, i) {
    var key = packet.source.key + "__" + packet.dest.key
    if (commsMap[key] == null) {
      commsMap[key] = initComm(packet.source, packet.dest)
      rows.push(commsMap[key])
    }

    var comm = commsMap[key],
        el   = document.createElement('div')
    el.classList.add('packet')

    switch (packet.header.protocol) {
      case 0x06: el.classList.add('tcp'); break
      case 0x11: el.classList.add('udp'); break
    }

    if (packet.udpHeader != null) {
      var u8 = new Uint8Array(packet.payload)
      if (u8[0] == 0xA1 && u8[1] == 0xAF ||
          u8[0] == 0xAF && u8[1] == 0xA1) {
        el.style.background = '#36C'
        switch (u8[2]) {
          case 0x44: case 0x14: // heartbeat
          case 0x63: case 0x13: // hangup
          case 0x40: case 0x10: // handshake
          case 0x61: case 0x11: // handshake2
            el.style.opacity = '0.4'
            break

          case 0x62: case 0x12: // data send/ack
            break

          default:
            el.style.background = ''
        }
      }

    } else if (packet.tcpHeader != null) {
      if (packet.payload.byteLength == 0) {
        el.style.opacity = '0.4'
      }
    }

    var t        = packet.time.sec + packet.time.usec/1e6 - t0,
        leftEdge = t * 5,
        width    = (Math.log(packet.header.length) - 3) * 6,
        delta    = Math.floor(leftEdge - comm.lastEdge)

    if (delta < 0) delta = 0

    el.style.width = width + 'px'
    el.style.marginLeft = delta + 'px'
    if (delta == 0) el.style.borderLeft = '0'
    comm.lastEdge += delta + width + (delta == 0? 1 : 2)

    el.addEventListener('click', getClickHandler(packet, t), false)
    comm.td.appendChild(el)

    packet.element = el
  })

  var maxLastEdge = 0
  for (var k in commsMap) {
    var comm = commsMap[k]
    if (comm.lastEdge > maxLastEdge) {
      maxLastEdge = comm.lastEdge
    }
  }

  var table = document.getElementById('packet-table')
  table.style.width = (maxLastEdge + 500) + 'px'
  rows.forEach(function (row) {
    table.appendChild(row.tr)
  })

  // scrollbar start
  var scrollbar = document.getElementById('scrollbar'),
      scrollbarCtx = scrollbar.getContext('2d')
  this.packets.forEach(function (packet) {
    var x0 = parseInt(webshark.packets[0].element.offsetLeft),
        x  = parseInt(packet.element.offsetLeft)

    var px = Math.floor((x - x0) * scrollbar.width / (maxLastEdge + 500)),
        pw = Math.max(2, Math.floor(parseInt(packet.element.style.width)
                            * scrollbar.width / (maxLastEdge + 500))),
        ph = scrollbar.height / Object.keys(commsMap).length,
        py = Object.keys(commsMap)
                   .indexOf(packet.source.key + "__" + packet.dest.key) * ph

    var el = packet.element
    var style = el.style.backgroundColor ||
               (el.classList.contains('udp')?  '#C00'
              : el.classList.contains('tcp')?  '#0C0'
              :                                '#666')
    scrollbarCtx.fillStyle = style
    scrollbarCtx.fillRect(px, py, pw, ph)
  })
  // scrollbar end

  function initComm(source, dest) {
    var tr = document.createElement('tr'),
        th = document.createElement('th'),
        td = document.createElement('td')

    tr.appendChild(th)
    tr.appendChild(td)
    td.classList.add('packet-area')

    th.appendChild(createHeading('Source', source))
    th.appendChild(createHeading('Destination', dest))

    return { source:   source,
             dest:     dest,
             tr:       tr,
             td:       td,
             lastEdge: 0 }

    function createHeading(caption, host) {
      var p      = document.createElement('p'),
          strong = document.createElement('strong'),
          ip     = document.createElement('span'),
          port   = document.createElement('span')

      ip.classList.add('ip')
      port.classList.add('port')

      p.appendChild(strong)
      p.appendChild(ip)
      p.appendChild(port)

      strong.appendChild(document.createTextNode(caption))
      port.appendChild(document.createTextNode(''))

      ip.appendChild(document.createTextNode(
        webshark.sprintf('%ip', host.ipv4)))

      return p
    }
  }

  function getClickHandler(packet, t) {
    return function () {
      var infoEl = document.getElementById('info'),
          hexdumpEl = document.getElementById('hexdump')
      infoEl.innerHTML = ''

      appendInfo('Time',   '%f',   t)
      appendInfo('Length', '%d',   packet.header.length)
      appendInfo('Source', '%ip',  packet.source.ipv4)
      appendInfo('Dest',   '%ip',  packet.dest.ipv4)
      appendInfo('Proto',  '%02x', packet.header.protocol)

      if (packet.udpHeader) {
        appendInfo(null)
        appendInfo("UDPLength", '%d', packet.udpHeader.length)
        appendInfo("UDPSource", '%d', packet.udpHeader.source_port)
        appendInfo("UDPDest",   '%d', packet.udpHeader.dest_port)

      } else if (packet.tcpHeader) {
        appendInfo(null)
        appendInfo("TCPSource",  '%d', packet.tcpHeader.source_port)
        appendInfo("TCPDest",    '%d', packet.tcpHeader.dest_port)
        appendInfo("TCPSeq",     '%d', packet.tcpHeader.sequence)
        appendInfo("TCPAck",     '%d', packet.tcpHeader.acknowledge)
        appendInfo("TCPFlags",   '%s',
          ['FIN', 'SYN', 'RST', 'PSH', 'ACK', 'URG', 'ECE', 'CWR', 'NS']
            .filter(function (_, i) {
              return (packet.tcpHeader.flags & (1 << i)) != 0 })
            .reverse()
            .join("|"))
        appendInfo("TCPDataOff", '%d', packet.tcpHeader.flags >> 12)
        appendInfo("TCPOptions", hexdump(packet.tcpHeader.options), 'block')
      }


      /* NOTE: temporary deciphering
      var db44Idx   = -1,
          u8        = new Uint8Array(packet.payload),
          payload   = packet.payload,
          highlight = []
      for (var i = 0; i < u8.length; i++) {
        if (u8[i] == 0x44 && u8[i + 1] == 0xdb) {
          db44Idx = i
          break
        }
      }
      if (db44Idx >= 2) {
        db44Idx -= 2

        var payload_ = packet.payload.slice(0),
            u8_      = new Uint8Array(payload_)

        var keystream = '0f 87 44 db .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. de 1c 5a ef b5 07 8a da 40 0e 76 7c c5 04 d3 9b 1b a5 94 ef ab e5 3c 55 .. .. .. .. 4c 82 55 85 .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ad e5 9b c7 .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. 4a ff fb 3b .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. f1 22 9b c2 .. .. .. .. .. .. .. .. .. .. .. .. .. .. 3c 12 6a ce .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. b1 3b 7a 6f .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. 1a 3b 9a 2e .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..'
                          .split(' ').map(function (s) { return s == '..'? null : parseInt(s, 16) })

        for (var i = 0; i < Math.min(keystream.length, u8.length - db44Idx); i++) {
          if (keystream[i] != null) {
            u8_[db44Idx + i] ^= keystream[i]
            highlight.push(db44Idx + i)
          }
        }

        payload = payload_
      }

      hexdumpEl.innerHTML = ''
      hexdumpEl.appendChild(hexdump(payload, highlight))
      /*/
      hexdumpEl.innerHTML = ''
      hexdumpEl.appendChild(hexdump(packet.payload))
      //*/

      function appendInfo(caption, fmt /*...*/) {
        if (caption == null) {
          var hr = document.createElement('hr')
          infoEl.appendChild(hr)
          return
        }

        var args = Array.prototype.slice.call(arguments, 1)
        var dt = document.createElement('dt'),
            dd = document.createElement('dd')

        dt.appendChild(document.createTextNode(caption))

        if (typeof fmt == 'string') {
          dd.appendChild(document.createTextNode(
            webshark.sprintf.apply(webshark, args)))

        } else if (fmt instanceof Node) {
          dd.appendChild(fmt)
          if (args[1] == 'block') {
            dt.classList.add('block')
          }

        } else {
          throw new Error("appendInfo: fmt is '" + fmt + "'.")
        }

        infoEl.appendChild(dt)
        infoEl.appendChild(dd)
      }
    }
  }
}



function fetchBlob(url, callback) {
  var xhr = new XMLHttpRequest()
  xhr.overrideMimeType('application/octet-stream')
  xhr.onreadystatechange = function () {
    if (xhr.readyState == 4) {
      callback(null, xhr.response, xhr)
    }
  }
  xhr.open('GET', url, true)
  xhr.responseType = 'blob'
  xhr.send()
}

//fetchBlob('data/sample-2.pcap', function (err, blob) {
//fetchBlob('data/sample-behold-2.pcap', function (err, blob) {
//fetchBlob('data/2014-12-06_homemenu-shop.pcap', function (err, blob) {
//fetchBlob('data/2014-12-09_pending-sysupdate.pcap', function (err, blob) {
fetchBlob('data/2014-12-10.pcap', function (err, blob) {
  if (err) throw err
  var reader = new FileReader()

  reader.onload = function () {
    var initiated = false

    var counter = 0
    readPcap(reader.result, function (err, header, recHeader, record) {
      if (err) throw err
      if (!initiated) {
        initiated = true
        webshark.begin(header)
      }
      webshark.feed(recHeader, record)
      counter++
    })

    webshark.end()
    console.log("Read %d records.", counter)
  }

  reader.readAsArrayBuffer(blob)
})

var scrollbar = document.getElementById('scrollbar'),
    table     = document.getElementById('packet-table')
scrollbar.width = window.innerWidth - 16
scrollbar.style.width = scrollbar.width + 'px'
scrollbar.addEventListener('mousemove', scrollbarHandler, false)
scrollbar.addEventListener('mousedown', scrollbarHandler, false)

function scrollbarHandler(ev) {
  if (ev.buttons != 1) return

  var x = ev.layerX * parseInt(table.style.width) / scrollbar.width
  window.scrollTo(x, window.scrollY)
}
