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
end
