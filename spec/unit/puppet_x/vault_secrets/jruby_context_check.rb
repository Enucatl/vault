# Run with the ML-DSA-enabled JRuby OpenSSL gem and ML-DSA TLS schemes enabled.
require 'tmpdir'
require 'set'
require_relative '../../../../lib/puppet_x/vault_secrets/vaultsession'

Puppet.initialize_settings

def certificate(key, name, issuer = nil, issuer_key = key)
  cert = OpenSSL::X509::Certificate.new
  cert.version = 2
  cert.serial = issuer ? 2 : 1
  cert.subject = OpenSSL::X509::Name.parse("/CN=#{name}")
  cert.issuer = issuer ? issuer.subject : cert.subject
  cert.public_key = OpenSSL::PKey.read(key.public_to_pem)
  cert.not_before = Time.now - 60
  cert.not_after = Time.now + 3600
  factory = OpenSSL::X509::ExtensionFactory.new
  factory.subject_certificate = cert
  factory.issuer_certificate = issuer || cert
  cert.add_extension(factory.create_extension('basicConstraints', issuer ? 'CA:FALSE' : 'CA:TRUE', true))
  cert.add_extension(factory.create_extension('subjectAltName', 'DNS:localhost')) if issuer
  cert.sign(issuer_key, OpenSSL::Digest.new('SHA256'))
  cert
end

def reject_tls
  yield
rescue OpenSSL::SSL::SSLError
  nil
else
  raise 'accepted an untrusted TLS identity'
end

ca_key = OpenSSL::PKey::RSA.new(2048)
ca = certificate(ca_key, 'Test CA')
key = OpenSSL::PKey.generate_key('ML-DSA-44')
cert = certificate(key, 'localhost', ca, ca_key)
context = OpenSSL::SSL::SSLContext.new(:TLS)
context.cert = cert
context.key = key
context.cert_store = OpenSSL::X509::Store.new.tap { |store| store.add_cert(ca) }
context.verify_mode = OpenSSL::SSL::VERIFY_PEER
context.min_version = context.max_version = OpenSSL::SSL::TLS1_3_VERSION
tcp = TCPServer.new('127.0.0.1', 0)
listener = OpenSSL::SSL::SSLServer.new(tcp, context)
port = tcp.addr[1]
requests = []
worker = Thread.new do
  loop do
    socket = nil
    begin
      socket = listener.accept
      first_line = socket.gets
      next unless first_line
      headers = {}
      while (line = socket.gets) && line != "\r\n"
        name, value = line.split(':', 2)
        headers[name.downcase] = value.strip
      end
      length = headers.fetch('content-length', '0').to_i
      body = length.zero? ? '' : socket.read(length)
      requests << [first_line.strip, headers, body, socket.peer_cert]
      path = first_line.split[1]
      payload = path.end_with?('/login') ? '{"auth":{"client_token":"client-token"}}' : '{"data":{"answer":"present"}}'
      status = path == '/redirect' ? "302 Found\r\nLocation: https://localhost:#{port}/followed" : '200 OK'
      socket.write("HTTP/1.1 #{status}\r\nContent-Length: #{payload.bytesize}\r\nConnection: close\r\n\r\n#{payload}")
    rescue OpenSSL::SSL::SSLError
      # Rejected clients send a TLS alert before HTTP.
    ensure
      socket.close if socket
    end
  end
end

begin
  Dir.mktmpdir('vault-jruby') do |dir|
    ca_file = File.join(dir, 'ca.pem')
    File.write(ca_file, ca.to_pem)
    other_file = File.join(dir, 'other.pem')
    File.write(other_file, certificate(OpenSSL::PKey::RSA.new(2048), 'Other CA').to_pem)
    # Token authentication must not read the configured host identity.
    Puppet[:hostcert] = File.join(dir, 'cert.pem')
    Puppet[:hostprivkey] = File.join(dir, 'key.pem')
    args = { 'uri' => "https://localhost:#{port}/secret", 'token' => 'test-token',
             'ca_trust' => ca_file, 'timeout' => 5 }
    client = VaultSession.new(args)
    raise 'GET response was not parsed' unless client.get == { 'answer' => 'present' }
    raise 'POST failed' unless client.post('/write', { 'value' => 'written' }).code.to_i == 200
    reject_tls { VaultSession.new(args.merge('ca_trust' => other_file)).get }
    reject_tls { VaultSession.new(args.merge('uri' => "https://127.0.0.1:#{port}/secret")).get }
    response = client.http.request(Net::HTTP::Get.new('/redirect'))
    raise 'redirect response was lost' unless response.code.to_i == 302
    File.write(Puppet[:hostcert], cert.to_pem)
    File.write(Puppet[:hostprivkey], key.private_to_pem)
    authenticated = VaultSession.new(args.reject { |name, _| name == 'token' }.merge('auth_path' => 'cert/', 'auth_name' => 'puppet'))
    raise 'authenticated GET failed' unless authenticated.get == { 'answer' => 'present' }
  end
ensure
  worker.kill
  worker.join
  listener.close
end
raise 'redirect was followed' if requests.any? { |request| request[0].include?('/followed') }
raise 'wrong HTTP requests' unless requests.map(&:first) == ['GET /secret HTTP/1.1', 'POST /write HTTP/1.1', 'GET /redirect HTTP/1.1', 'POST /v1/auth/cert/login HTTP/1.1', 'GET /secret HTTP/1.1']
raise 'token header was lost' unless requests.first[1]['x-vault-token'] == 'test-token'
raise 'POST body was lost' unless JSON.parse(requests[1][2]) == { 'value' => 'written' }
raise 'certificate role was lost' unless JSON.parse(requests[3][2]) == { 'name' => 'puppet' }
raise 'ML-DSA client identity was lost' unless requests[3][3].to_der == cert.to_der
raise 'certificate authentication token was lost' unless requests[4][1]['x-vault-token'] == 'client-token'
puts 'JRUBY_MLDSA_CONTEXT_PASS'
