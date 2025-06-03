# frozen_string_literal: true

require 'json'
require 'digest'
# require 'byebug'

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
  data.each { |ele| encoded_str << encode_bencode(ele) }
  encoded_str += 'e'
  encoded_str
end

def encode_dict(data)
  encoded_str = 'd'
  data.sort.each { |key, val| encoded_str += "#{encode_bencode(key)}#{encode_bencode(val)}" }
  encoded_str += 'e'
  encoded_str
end

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

command = ARGV[0]

if command == 'decode'
  # You can use print statements as follows for debugging, they'll be visible when running tests.
  # $stderr.puts 'Logs from your program will appear here'

  # Uncomment this block to pass the first stage
  encoded_str = ARGV[1]
  decoded_str, = decode_bencode(encoded_str)
  puts JSON.generate(decoded_str)
elsif command == 'info'
  torrent_path = ARGV[1]
  encoded_str = File.binread(torrent_path)
  decoded_str, = decode_bencode(encoded_str)
  torrent_info = decoded_str['info']
  encode_info = encode_bencode(torrent_info)
  info_hash = Digest::SHA1.hexdigest(encode_info)

  puts "Tracker URL: #{decoded_str['announce']}"
  puts "Length: #{decoded_str['info']['length']}"
  puts "Info Hash: #{info_hash}"
end
