# frozen_string_literal: true

require 'json'
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

  puts "Tracker URL: #{decoded_str['announce']}"
  puts "Length: #{decoded_str['info']['length']}"
end
