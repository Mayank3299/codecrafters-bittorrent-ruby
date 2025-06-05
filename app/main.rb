# frozen_string_literal: true

require 'json'
require 'digest'
require 'uri'
require 'net/http'
require 'securerandom'
require 'socket'
# require 'byebug'

BITTORRENT_MESSAGE_ID_HASH = {
  'choke' => 0,
  'unchoke' => 1,
  'interested' => 2,
  'not interested' => 3,
  'have' => 4,
  'bitfield' => 5,
  'request' => 6,
  'piece' => 7,
  'cancel' => 8
}.freeze

BLOCK_SIZE = 16 * 1024 # 16 KB = 16,384

if ARGV.length < 2
  puts 'Usage: your_program.sh <command> <args>'
  exit(1)
end

def decode_str(bencoded_value)
  raise ArgumentError, 'Invalid encoded value' unless bencoded_value.include?(':')

  str_size, rest = bencoded_value.split(':', 2)
  string = rest[...str_size.to_i]
  [string, rest[str_size.to_i..]]
end

def decode_int(bencoded_value)
  raise ArgumentError, 'Invalid encoded value' unless bencoded_value.include?('e')

  bencoded_value = bencoded_value[1..]
  number, rest = bencoded_value.split('e', 2)
  [number.to_i, rest]
end

def decode_list(bencoded_value)
  raise ArgumentError, 'Invalid encoded value' unless bencoded_value.include?('e')

  bencoded_value = bencoded_value[1..]
  list = []
  rest = bencoded_value
  until rest[0] == 'e'
    item, rest = decode_bencode(rest)
    list << item
  end
  [list, rest[1..]]
end

def decode_dict(bencoded_value)
  raise ArgumentError, 'Invalid encoded value' unless bencoded_value.include?('e')

  bencoded_value = bencoded_value[1..]
  hash = {}
  rest = bencoded_value
  until rest[0] == 'e'
    key, rest = decode_bencode(rest)
    value, rest = decode_bencode(rest)

    hash[key] = value
  end
  [hash, rest[1..]]
end

def decode_bencode(bencoded_value)
  case bencoded_value[0]
  when /\d/
    decode_str(bencoded_value)
  when /i/
    decode_int(bencoded_value)
  when /l/
    decode_list(bencoded_value)
  when /d/
    decode_dict(bencoded_value)
  end
end

def encode_str(data)
  "#{data.length}:#{data}"
end

def encode_int(data)
  "i#{data}e"
end

def encode_list(data)
  encoded_str = 'l'
  data.each { |ele| encoded_str += encode_bencode(ele) }
  encoded_str += 'e'
  encoded_str
end

def encode_dict(data)
  encoded_str = 'd'
  data.sort.each { |key, val| encoded_str += "#{encode_bencode(key)}#{encode_bencode(val)}" }
  encoded_str += 'e'
  encoded_str
end

# rubocop:disable Metrics/MethodLength
def encode_bencode(data)
  case data
  when String, Symbol
    encode_str(data)
  when Integer
    encode_int(data)
  when Array
    encode_list(data)
  when Hash
    encode_dict(data)
  else
    raise ArgumentError, "Cannot bencode data type: #{data.class}"
  end
end
# rubocop:enable Metrics/MethodLength

def parse_torrent_file(torrent_path)
  # Parsing torrent file
  encoded_str = File.binread(torrent_path)
  decoded_str, = decode_bencode(encoded_str)
  decoded_str
end

def encode_and_digest_info_hash(decoded_str, hex_digest: false)
  # Encode info hash with url encoding
  encoded_info = encode_bencode(decoded_str['info'])
  hex_digest ? Digest::SHA1.hexdigest(encoded_info) : Digest::SHA1.digest(encoded_info)
end

# rubocop:disable Metrics/MethodLength
def peer_string(decoded_str)
  # Getting tracker url in URI
  tracker_url = decoded_str['announce']
  url = URI.parse(tracker_url)

  info_hash = encode_and_digest_info_hash(decoded_str)

  # Params for tracker get request
  peer_id = SecureRandom.hex(10)
  params = {
    'info_hash' => info_hash,
    'peer_id' => peer_id,
    'port' => 6881,
    'uploaded' => 0,
    'downloaded' => 0,
    'left' => decoded_str['info']['length'],
    'compact' => 1
  }

  # Adding query params
  url.query = URI.encode_www_form(params)

  # Getting response and decoding it
  response = Net::HTTP.get_response(url)
  decoded_response = decode_bencode(response.body).first

  # Get peers in bytes, each is 6 bytes-> 4-IP,2-PORT, unpack them and getting the peers
  decoded_response['peers']
end
# rubocop:enable Metrics/MethodLength

def discover_peers(peers)
  peers.unpack('C*').each_slice(6).map do |slice|
    ip = slice[0..3].join('.')
    port = (slice[4] << 8) + slice[5]
    "#{ip}:#{port}"
  end
end

def build_handshake(info_hash, peer_id)
  bt_protocol = 'BitTorrent protocol'
  reserved_bytes = "\x00" * 8
  bt_protocol.length.chr + bt_protocol + reserved_bytes + info_hash + peer_id
end

def valid_handshake?(response, info_hash)
  response.bytesize == 68 && response[28..47] == info_hash
end

# rubocop:disable Metrics/MethodLength
def peer_handshake(peer_ip, peer_port, info_hash)
  socket = TCPSocket.new(peer_ip, peer_port)
  peer_id = SecureRandom.hex(10)
  handshake = build_handshake(info_hash, peer_id)
  socket.write(handshake)

  response = socket.read(68)
  if valid_handshake?(response, info_hash)
    [response[48..].unpack1('H*'), socket, true]
  else
    socket.close
    [nil, nil, false]
  end
end
# rubocop:enable Metrics/MethodLength

def read_until(socket, message_id)
  loop do
    message = read_peer_message(socket)
    return if message[:id] == message_id
  end
end

def read_peer_message(socket)
  message_length = socket.read(4).unpack1('N*')
  return { id: nil, payload: nil } if message_length.nil?

  message_id = socket.read(1).unpack1('C')
  payload = socket.read(message_length - 1)

  { id: message_id, payload: payload }
end

def send_peer_message(socket, id, payload: '')
  length = [1 + payload.bytesize].pack('N')
  message = length + [id].pack('C') + payload
  socket.write(message)
end

# rubocop:disable Metrics/MethodLength, Metrics/AbcSize
def piece_download(socket, info_hash, piece_index)
  piece_length = info_hash['piece length']
  total_length = info_hash['length']
  no_of_pieces = (info_hash['pieces'].bytesize / 20) - 1 # Pieces with length 20
  current_piece_length = piece_index < no_of_pieces ? piece_length : total_length - no_of_pieces * piece_length

  (0...current_piece_length).step(BLOCK_SIZE) do |offset|
    length = [BLOCK_SIZE, current_piece_length - offset].min # last block might be smaller
    payload = [piece_index, offset, length].pack('N3')
    # Send request message
    send_peer_message(socket, BITTORRENT_MESSAGE_ID_HASH['request'], payload: payload)
  end

  piece_data = "\x00" * current_piece_length
  received_bytes = 0

  until received_bytes >= current_piece_length
    message = read_peer_message(socket)
    next if message[:id] != BITTORRENT_MESSAGE_ID_HASH['piece']

    payload = message[:payload]
    # piece_index = payload[1, 4].unpack1('N')
    piece_offset = payload[4, 4].unpack1('N')
    block_data = payload[8..] # everything after the 9th byte

    piece_data[piece_offset, block_data.bytesize] = block_data
    received_bytes += block_data.length
  end

  piece_data
end

def validate_piece_data(info_hash, piece_index, piece_data)
  expected_hash = info_hash['pieces'].byteslice(piece_index * 20, 20)
  output_hash = Digest::SHA1.digest(piece_data)
  raise 'Piece hash mismatch' if output_hash != expected_hash # raise error if the hashes don't match
end

def handle_peer_messages(socket, info_hash, output_path, piece_index)
  # Waiting to receive bitfield message
  read_until(socket, BITTORRENT_MESSAGE_ID_HASH['bitfield'])
  # Send interested message
  send_peer_message(socket, BITTORRENT_MESSAGE_ID_HASH['interested'])
  # Waiting to receive unchoke message
  read_until(socket, BITTORRENT_MESSAGE_ID_HASH['unchoke'])
  # Download piece in blocks
  piece_data = piece_download(socket, info_hash, piece_index)
  # Validate received piece hash with torrent info_hash's piece hash
  validate_piece_data(info_hash, piece_index, piece_data)

  File.open(output_path, 'wb') { |f| f.write(piece_data) }
  puts "Piece #{piece_index} downloaded to #{output_path}."
  socket.close
rescue StandardError => e
  puts "Error: #{e.message}"
end
# rubocop:enable Metrics/MethodLength, Metrics/AbcSize

command = ARGV[0]

case command
when 'decode'
  # You can use print statements as follows for debugging, they'll be visible when running tests.
  # $stderr.puts 'Logs from your program will appear here'

  # Uncomment this block to pass the first stage
  encoded_str = ARGV[1]
  decoded_str, = decode_bencode(encoded_str)
  puts JSON.generate(decoded_str)
when 'info'
  torrent_path = ARGV[1]
  decoded_str = parse_torrent_file(torrent_path)
  info_hash = encode_and_digest_info_hash(decoded_str, hex_digest: true)

  puts "Tracker URL: #{decoded_str['announce']}"
  puts "Length: #{decoded_str['info']['length']}"
  puts "Info Hash: #{info_hash}"
  puts "Piece Length: #{decoded_str['info']['piece length']}"
  # String of SHA1 hashes, each of 40 bytes in hexadecimal
  puts "Piece Hashes: #{decoded_str['info']['pieces'].unpack1('H*').scan(/.{40}/)}"
when 'peers'
  torrent_path = ARGV[1]
  decoded_str = parse_torrent_file(torrent_path)
  peers = peer_string(decoded_str)
  peers_data = discover_peers(peers)

  puts peers_data
when 'handshake'
  torrent_path = ARGV[1]
  peer_ip, peer_port = ARGV[2].split(':', 2)

  decoded_str = parse_torrent_file(torrent_path)
  info_hash = encode_and_digest_info_hash(decoded_str)

  hex_peer_id, = peer_handshake(peer_ip, peer_port, info_hash)
  puts "Peer ID: #{hex_peer_id}"
when 'download_piece'
  if ARGV.length < 5
    puts 'Usage: your_program.sh <command> -o <output_file> <torrent_file> <piece_index>'
    exit(1)
  end

  output_path = ARGV[2]
  torrent_path = ARGV[3]
  piece_index = ARGV[4].to_i

  decoded_str = parse_torrent_file(torrent_path)
  info_hash = encode_and_digest_info_hash(decoded_str)

  peers = peer_string(decoded_str)
  peers_data = discover_peers(peers)

  peer = peers_data.first
  peer_ip, peer_port = peer.split(':', 2)

  _, socket, peer_handshake_valid = peer_handshake(peer_ip, peer_port, info_hash)
  handle_peer_messages(socket, decoded_str['info'], output_path, piece_index) if peer_handshake_valid
end
