require 'uri'
require 'net/http'

uri = URI('https://www.google.com/')
res = Net::HTTP.get_response(uri)
puts res.body if res.is_a?(Net::HTTPSuccess)
