require 'openssl'
require 'net/http'
require 'json'
require 'json/jwt'
require 'SecureRandom'

key = OpenSSL::PKey::RSA.new 2048
deviceId = SecureRandom.random_number(99999)

payload = {
    OldSyncKey: SecureRandom.random_number(99999),
    NewSyncKey: SecureRandom.random_number(99999)
}

puts "device id: #{deviceId}"

# Registration

uri = URI('http://localhost:8081/api/v1/application')
http = Net::HTTP.new(uri.host, uri.port)
req = Net::HTTP::Post.new(uri.path, 'Content-Type' => 'application/json')
jwk = key.public_key.to_jwk

req.body = {
    Id: deviceId, 
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

puts "registration completed"

while true 
    shouldRoll = true
    
    #payload rolling
    payload[:OldSyncKey] = payload[:NewSyncKey]
    payload[:NewSyncKey] = SecureRandom.random_number(99999)

    #token request
    token = JSON::JWT.new(payload).sign(key, :RS256)
    puts 'requesting token'
    uri = URI('http://localhost:8081/connect/token')
    res = Net::HTTP.post_form(uri, 
        'client_id' => 'ruby', 
        #secret is required by OpenId, but has no meaning
        'client_secret' => 'secret', 
        'grant_type' => 'jwt-otp', 
        'scope' => 'sensitive.read', 
        'device-id' => deviceId, 
        'signature' => token.to_s)

    if (!res.kind_of? Net::HTTPSuccess)
        #Handling errors!
        if (res.kind_of? Net::HTTPBadRequest)
            puts "bad request"
        else
            shouldRoll = false
            puts "failed to get token"
            puts res
        end

        next
    end
    
    shouldRoll = true
    token = JSON.parse(res.body)['access_token']

    puts 'token received'
    puts "let's get some sensitive data! enter deviceId:"
    forDeviceId = gets.chomp

    #accessing sensitive api with the token
    uri = URI("http://localhost:8082/api/v1/sensitive/#{forDeviceId}")
    req = Net::HTTP::Get.new(uri)    
    req['Authorization'] = "Bearer #{token}"
    http = Net::HTTP.new(uri.host, uri.port)    
    res = http.request(req)

    if (!res.kind_of? Net::HTTPSuccess)
        if (res.kind_of? Net::HTTPUnauthorized)
            puts "You are not authorized to read sensitive data for device #{forDeviceId}"
            next
        end
        puts res
        exit(1)
    end

    puts "Response from sensitive api: #{res.body}"

    puts 'press q to exit or any key to continue'

    if gets.chomp == 'q'
        exit(0)
    end
end 