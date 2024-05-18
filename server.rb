require 'socket'
require 'digest/sha1'

server = TCPServer.new('localhost', 2345)

loop do
  socket = server.accept
  STDERR.puts "Incoming Request"

  http_request = ""
  while (line = socket.gets) && (line.chomp != '')
    http_request += line
  end

  STDERR.puts http_request

  if matches = http_request.match(/^Sec-WebSocket-Key: (\S+)/)
    websocket_key = matches[1]
    STDERR.puts "WebSocket handshake detected with key: #{websocket_key}"
  else
    STDERR.puts "Aborting non-websocket connection"
    socket.close
  end

  response_key = Digest::SHA1.base64digest([websocket_key, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"].join)
  STDERR.puts "Responding with handshake with key: #{response_key}"

  socket.write <<~EOS
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: #{response_key}

EOS
  STDERR.puts "Handshake completed."

  first_byte = socket.getbyte
  fin = first_byte & 0x80
  opcode = first_byte & 0x0F

  raise "We don't support continuations" unless fin
  raise "We only support opcode 1" unless opcode == 1

  second_byte = socket.getbyte
  is_masked = second_byte & 0x80
  payload_size = second_byte & 0x7F

  raise "All incoming frames should be masked according to the websocket spec" unless is_masked
  raise "We only support payloads < 126 bytes in length" unless payload_size < 126

  STDERR.puts "Reading a #{payload_size} byte payload"

  mask = 4.times.map { socket.getbyte }
  STDERR.puts "Got mask: #{mask.inspect}"

  payload = payload_size.times.map { socket.getbyte }
  STDERR.puts "Got masked payload: #{payload.inspect}"

  unmasked_payload = payload.each_with_index.map { |b, i| b ^ mask[i % 4] }
  STDERR.puts "Unmasked payload: #{unmasked_payload.inspect}"
  STDERR.puts "Converted payload: #{unmasked_payload.pack('C*').force_encoding('utf-8').inspect}"

  response = "You said: #{unmasked_payload.pack('C*').force_encoding('utf-8').inspect}"
  STDERR.puts "Sending response: #{response.inspect}"

  output = [0b10000001, response.size, response]
  socket.write output.pack("CCA#{ response.size }")
end
