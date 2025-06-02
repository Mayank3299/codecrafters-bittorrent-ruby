# frozen_string_literal: true

require 'json'
# require 'byebug'

if ARGV.length < 2
  puts 'Usage: your_program.sh <command> <args>'
  exit(1)
end

def decode_bencode(bencoded_value)
  # debugger
  if bencoded_value[0].chr.match?(/\d/)
    first_colon = bencoded_value.index(':')
    raise ArgumentError, 'Invalid encoded value' if first_colon.nil?

    bencoded_value[first_colon + 1..]
  else
    puts 'Only strings are supported at the moment'
    exit(1)
  end
end

command = ARGV[0]

if command == 'decode'
  # You can use print statements as follows for debugging, they'll be visible when running tests.
  # $stderr.puts 'Logs from your program will appear here'

  # Uncomment this block to pass the first stage
  encoded_str = ARGV[1]
  decoded_str = decode_bencode(encoded_str)
  puts JSON.generate(decoded_str)
end
