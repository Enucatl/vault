require 'spec_helper'
require 'tempfile'

require_relative '../../../../lib/puppet_x/vault_secrets/vaultsession'

describe VaultSession do
  subject(:session) { described_class.allocate }

  let(:certificate) do
    key = OpenSSL::PKey::RSA.new(2048)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 1
    cert.subject = OpenSSL::X509::Name.parse('/CN=Spec CA')
    cert.issuer = cert.subject
    cert.public_key = key.public_key
    cert.not_before = Time.now
    cert.not_after = Time.now + 3600
    cert.sign(key, OpenSSL::Digest.new('SHA256'))
    cert
  end

  def with_bundle(contents)
    Tempfile.create('ca-bundle') do |file|
      file.write(contents)
      file.flush
      yield file.path
    end
  end

  it 'loads certificates from a bundle containing comments' do
    with_bundle("# managed certificate bundle\n#{certificate.to_pem}") do |path|
      store = session.get_cert_store(path)

      expect(store.verify(certificate)).to be true
    end
  end

  it 'ignores duplicate certificates' do
    with_bundle(certificate.to_pem * 2) do |path|
      store = session.get_cert_store(path)

      expect(store.verify(certificate)).to be true
    end
  end

  it 'skips malformed certificates when a valid certificate remains' do
    malformed = "-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n"
    with_bundle("#{malformed}#{certificate.to_pem}") do |path|
      store = session.get_cert_store(path)

      expect(store.verify(certificate)).to be true
    end
  end

  it 'rejects a missing explicit bundle' do
    expect {
      session.get_cert_store('/missing/ca-bundle.pem')
    }.to raise_error(Puppet::Error, %r{does not exist})
  end

  it 'uses an explicitly supplied CA bundle' do
    allow(File).to receive(:file?).with('/explicit/ca-bundle.pem').and_return(true)

    expect(session.get_ca_file('/explicit/ca-bundle.pem')).to eq '/explicit/ca-bundle.pem'
  end

  it 'rejects a missing explicitly supplied CA bundle' do
    allow(File).to receive(:file?).with('/missing/ca-bundle.pem').and_return(false)

    expect {
      session.get_ca_file('/missing/ca-bundle.pem')
    }.to raise_error(Puppet::Error, %r{does not exist})
  end

  it 'preserves upstream system bundle selection when no bundle is supplied' do
    redhat_bundle = '/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem'
    debian_bundle = '/etc/ssl/certs/ca-certificates.crt'
    allow(File).to receive(:file?).with(redhat_bundle).and_return(false)
    allow(File).to receive(:file?).with(debian_bundle).and_return(true)

    expect(session.get_ca_file(nil)).to eq debian_bundle
  end

  it 'allows TLS 1.3 while retaining a TLS 1.2 minimum and peer verification' do
    with_bundle(certificate.to_pem) do |path|
      client = described_class.new('uri' => 'https://vault.example/v1/kv/data/puppet',
                                   'token' => 'test-token', 'ca_trust' => path)

      expect(client.http.min_version).to eq OpenSSL::SSL::TLS1_2_VERSION
      expect(client.http.max_version).to be_nil
      expect(client.http.verify_mode).to eq OpenSSL::SSL::VERIFY_PEER
    end
  end

  it 'loads a non-RSA client key for certificate authentication' do
    key = OpenSSL::PKey::EC.generate('prime256v1')
    with_bundle(certificate.to_pem) do |cert_path|
      with_bundle(key.to_pem) do |key_path|
        allow(Puppet.settings).to receive(:[]).with(:hostcert).and_return(cert_path)
        allow(Puppet.settings).to receive(:[]).with(:hostprivkey).and_return(key_path)
        session.http = Net::HTTP.new('vault.example', 8200)
        allow(session).to receive(:post).with('/v1/auth/cert/login', { name: 'puppet-server' })
          .and_return(Net::HTTPOK.new('1.1', '200', 'OK').tap do |response|
            response.instance_variable_set(:@read, true)
            response.body = '{"auth":{"client_token":"test-token"}}'
          end)

        expect(session.get_token('cert/', 'puppet-server')).to eq 'test-token'
        expect(session.http.key).to be_a OpenSSL::PKey::EC
      end
    end
  end

  it 'preserves a server TLS 1.3-only policy and configured timeouts' do
    stub_const('Puppet::Server::HttpClient', Class.new)
    allow(Puppet::Server::HttpClient).to receive(:settings).and_return('ssl_protocols' => ['TLSv1.3'])
    with_bundle(certificate.to_pem) do |path|
      client = described_class.new('uri' => 'https://vault.example', 'token' => 'test-token', 'ca_trust' => path, 'timeout' => 7)

      expect(client.http.min_version).to eq OpenSSL::SSL::TLS1_3_VERSION
      expect(client.http.max_version).to eq OpenSSL::SSL::TLS1_3_VERSION
      expect(client.http.open_timeout).to eq 7
      expect(client.http.read_timeout).to eq 7
    end
  end

  [['TLSv1', 'TLSv1.3'], ['SSLv3'], []].each do |protocols|
    it "rejects unsupported server TLS policy #{protocols.inspect}" do
      stub_const('Puppet::Server::HttpClient', Class.new)
      allow(Puppet::Server::HttpClient).to receive(:settings).and_return('ssl_protocols' => protocols)
      with_bundle(certificate.to_pem) do |path|
        expect {
          described_class.new('uri' => 'https://vault.example', 'token' => 'test-token', 'ca_trust' => path)
        }.to raise_error(Puppet::Error, /server TLS protocol/)
      end
    end
  end

  it 'checks HTTP response status codes' do
    session.fail_hard = true
    response = double('server response', code: 403, body: '{"errors":["denied"]}')

    expect { session.err_check(response) }.to raise_error(Puppet::Error, /403/)
  end

  [nil, false].each do |token|
    it "keeps certificate authentication when token is #{token.inspect}" do
      with_bundle(certificate.to_pem) do |path|
        expect_any_instance_of(described_class).to receive(:get_token).with('cert', nil).and_return('client-token')

        described_class.new('uri' => 'https://vault.example/v1/kv/data/puppet',
                            'ca_trust' => path, 'auth_path' => 'cert', 'token' => token)
      end
    end
  end

  it 'preserves proxy routing' do
    http = Net::HTTP::Proxy('proxy.example', 3128).new('vault.example', 443)
    allow(Net::HTTP).to receive(:new).and_return(http)

    with_bundle(certificate.to_pem) do |path|
      client = described_class.new('uri' => 'https://vault.example/v1/kv/data/puppet',
                                   'token' => 'test-token', 'ca_trust' => path)
      expect(client.http.proxy_address).to eq('proxy.example')
      expect(client.http.proxy_port).to eq(3128)
    end
  end

  it 'honors no_proxy for the Vault host' do
    allow(ENV).to receive(:[]).and_call_original
    allow(ENV).to receive(:[]).with('http_proxy').and_return('http://proxy.example:3128')
    allow(ENV).to receive(:[]).with('no_proxy').and_return('vault.example')

    with_bundle(certificate.to_pem) do |path|
      client = described_class.new('uri' => 'https://vault.example/v1/kv/data/puppet',
                                   'token' => 'test-token', 'ca_trust' => path)
      expect(client.http.proxy?).to be(false)
    end
  end
end
