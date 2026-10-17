# Run with the OpenVox Server classpath and a generated ML-DSA identity directory.
require 'puppet/server/http_client'
require_relative '../../../../lib/puppet_x/vault_secrets/vaultsession'

Puppet.initialize_settings
Puppet[:hostcert] = File.join(ARGV.fetch(0), 'cert.pem')
Puppet[:hostprivkey] = File.join(ARGV.fetch(0), 'key.pem')

session = VaultSession.new('uri' => 'https://localhost:8200/v1/kv/data/puppet',
                           'token' => 'test-token', 'ca_trust' => Puppet[:hostcert], 'timeout' => 7)
session.configure_java_http(Puppet[:hostcert], 7, false)
options = session.instance_variable_get(:@java_options)
raise 'wrong connect timeout' unless options.get_connect_timeout_milliseconds == 7000
raise 'wrong read timeout' unless options.get_socket_timeout_milliseconds == 7000
raise 'redirects enabled' if options.get_follow_redirects
context = options.get_ssl_context
raise 'wrong TLS provider' unless context.provider.name == 'BCJSSE'
puts "ML-DSA context: #{context.provider}, #{context.create_ssl_engine.java_class.name}"

def reject_tls
  yield
rescue StandardError => error
  cause = error
  loop do
    return if cause.kind_of?(Java::JavaxNetSsl::SSLException)
    next_cause = cause.respond_to?(:getCause) ? cause.getCause : cause.cause
    raise error unless next_cause && next_cause != cause
    cause = next_cause
  end
else
  raise 'accepted an untrusted TLS identity'
end

listener = context.server_socket_factory.create_server_socket(0, 10, java.net.InetAddress.get_by_name('127.0.0.1'))
port = listener.local_port
requests = []
worker = Thread.new do
  loop do
    socket = listener.accept
    begin
      socket.so_timeout = 5000
      reader = java.io.BufferedReader.new(java.io.InputStreamReader.new(socket.input_stream))
      first_line = reader.read_line
      next unless first_line
      headers = {}
      while (line = reader.read_line) && !line.empty?
        name, value = line.split(':', 2)
        headers[name.downcase] = value.strip
      end
      body = Java::char[headers.fetch('content-length', '0').to_i].new
      offset = 0
      while offset < body.length
        count = reader.read(body, offset, body.length - offset)
        raise 'incomplete request body' if count < 0
        offset += count
      end
      requests << [first_line, headers, body.to_a.map(&:chr).join]
      redirect = first_line.split[1] == '/redirect'
      payload = '{"data":{"answer":"present"}}'
      status = redirect ? "302 Found\r\nLocation: https://localhost:#{port}/followed" : '200 OK'
      response = "HTTP/1.1 #{status}\r\nContent-Length: #{payload.bytesize}\r\nConnection: close\r\n\r\n#{payload}"
      socket.output_stream.write(response.to_java_bytes)
      socket.output_stream.flush
    rescue Java::JavaxNetSsl::SSLException, Java::OrgBouncycastleTls::TlsFatalAlert
      # Rejected clients can send a TLS alert before sending HTTP.
    ensure
      socket.close
    end
  end
rescue Java::JavaNet::SocketException
  raise unless listener.closed?
end

begin
  # Token authentication must not read the configured host identity.
  ca_file = Puppet[:hostcert]
  Puppet[:hostcert] = File.join(ARGV.fetch(0), 'missing-cert.pem')
  Puppet[:hostprivkey] = File.join(ARGV.fetch(0), 'missing-key.pem')
  args = { 'uri' => "https://localhost:#{port}/secret", 'token' => 'test-token',
           'ca_trust' => ca_file, 'timeout' => 5 }
  client = VaultSession.new(args)
  raise 'GET response was not parsed' unless client.get == { 'answer' => 'present' }
  raise 'POST failed' unless client.post('/write', { 'value' => 'written' }).code.to_i == 200
  reject_tls { VaultSession.new(args.merge('ca_trust' => File.join(ARGV.fetch(0), 'other.pem'))).get }
  reject_tls { VaultSession.new(args.merge('uri' => "https://127.0.0.1:#{port}/secret")).get }
  response = client.request_response(Net::HTTP::Get.new('/redirect'))
  raise 'redirect response was lost' unless response.code.to_i == 302
ensure
  listener.close
  worker.value
end
raise 'redirect was followed' if requests.any? { |request| request[0].include?('/followed') }
raise 'wrong HTTP requests' unless requests.map(&:first) == ['GET /secret HTTP/1.1', 'POST /write HTTP/1.1', 'GET /redirect HTTP/1.1']
raise 'token header was lost' unless requests.first[1]['x-vault-token'] == 'test-token'
raise 'POST body was lost' unless JSON.parse(requests[1][2]) == { 'value' => 'written' }
puts 'JRUBY_MLDSA_CONTEXT_PASS'
