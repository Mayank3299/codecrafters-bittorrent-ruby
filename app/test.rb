require 'byebug'

def encode_str(data)
  "#{data.length}:#{data}"
end

def encode_int(data)
  "i#{data}e"
end

def encode_list(data)
  encoded_str = 'l'
  data.each { |ele| encoded_str << encode_bencode(ele) }
  encoded_str << 'e'
  encoded_str
end

def encode_dict(data)
  encoded_str = 'd'
  data.sort.each { |key, val| encoded_str << "#{encode_bencode(key)}#{encode_bencode(val)}" }
  encoded_str << 'e'
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

data = {
  "name": "example.txt",
  "length": 123456,
  "piece length": 262144,
  "pieces": "0123456789abcdef01230123456789abcdef0123"
}

puts encode_bencode(data)
