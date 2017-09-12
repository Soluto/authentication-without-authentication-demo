require 'openssl'
require 'net/http'
require 'jwt'
require 'json/jwt'

if (!File.exists?('key.pem'))
    key = OpenSSL::PKey::RSA.new 2048
    file = File.open('key.pem', 'w')
    file.write(key.to_pem)
    uri = URI('http://localhost:5000/api/v1/application')
    http = Net::HTTP.new(uri.host, uri.port)
    req = Net::HTTP::Post.new(uri.path, 'Content-Type' => 'application/json')
    jwk = key.public_key.to_jwk
    req.body = {
        Id: '1', 
        OldSyncKey: 1,
        NewSyncKey: 2,
        PublicKey: {
            "kty": "RSA",
            "e": jwk['e'],
            "n": jwk['n']
        }
    }.to_json
    res = http.request(req)
    puts "response #{res.body}"
else 
    key = OpenSSL::PKey::RSA.new File.read 'key.pem'
end

payload = {
    :NewSyncKey => 1,
    :OldSyncKey => 2
}

token = JSON::JWT.new(payload).sign(key, :RS256)

uri = URI('http://localhost:5000/connect/token')
res = Net::HTTP.post_form(uri, 'client_id' => 'ruby', 'client_secret' => 'secret', 'grant_type' => 'jwt-otp', 'scope' => 'api1', 'app-id' => '1', 'jwt' => token.to_s)
puts res.body