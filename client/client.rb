require 'openssl'
require 'net/http'
require 'json'
require 'json/jwt'
require 'SecureRandom'

key = OpenSSL::PKey::RSA.new 2048
appId = SecureRandom.random_number(99999)

payload = {
    OldSyncKey: SecureRandom.random_number(99999),
    NewSyncKey: SecureRandom.random_number(99999)
}
#provision

uri = URI('http://localhost:5000/api/v1/application')
http = Net::HTTP.new(uri.host, uri.port)
req = Net::HTTP::Post.new(uri.path, 'Content-Type' => 'application/json')
jwk = key.public_key.to_jwk

req.body = {
    Id: appId, 
    OldSyncKey: payload[:OldSyncKey],
    NewSyncKey: payload[:NewSyncKey],
    PublicKey: {
        "kty": "RSA",
        "e": jwk['e'],
        "n": jwk['n']
    }
}.to_json
res = http.request(req)

if (!res.kind_of? Net::HTTPSuccess)
    puts res    
    exit(1)
end

while true 
    puts 'requesting token'
    payload[:OldSyncKey] = payload[:NewSyncKey]
    payload[:NewSyncKey] = SecureRandom.random_number(99999)

    token = JSON::JWT.new(payload).sign(key, :RS256)

    uri = URI('http://localhost:5000/connect/token')
    res = Net::HTTP.post_form(uri, 'client_id' => 'ruby', 'client_secret' => 'secret', 'grant_type' => 'jwt-otp', 'scope' => 'sensitive.read', 'app-id' => appId, 'jwt' => token.to_s)

    if (!res.kind_of? Net::HTTPSuccess)
        puts res.body
        exit(1)
    end
    token = JSON.parse(res.body)['access_token']

    uri = URI('http://localhost:4000/api/v1/sensitive')
    req = Net::HTTP::Get.new(uri)    
    req['Authorization'] = "Bearer #{token}"
    http = Net::HTTP.new(uri.host, uri.port)    
    res = http.request(req)

    if (!res.kind_of? Net::HTTPSuccess)
        puts res
        exit(1)
    end

    puts "sensitive data! #{res.body}"

    puts 'press q to exit or any key to continue'

    if gets.chomp == 'q'
        exit(0)
    end
end 