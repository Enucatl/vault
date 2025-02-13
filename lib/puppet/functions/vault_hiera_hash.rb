# frozen_string_literal: true

# Custom hiera back-end for Hashicorp Vault key/value secrets engines v1 and v2
Puppet::Functions.create_function(:vault_hiera_hash) do
  # @param options uri, ca_trust, token_file, auth_path, version, timeout, fail_hard
  # @option options [String] :uri        Required. The complete URL to the API endpoint for Hashicorp Vault key/value secrets.
  # @option options [String] :ca_trust   Optional path to a trusted CA certificate chain file.  Will try system defaults for RedHat/Debian if not set.
  # @option options [String] :token_file The path to a file that contains a Vault token. When not defined it will try PKI auth with Puppet cert.
  # @option options [String] :auth_path  Optional. The Vault path for the "cert" authentication type used with Puppet certificates.
  # @option options [String] :version    The Vault key/value secrets engine will always use 'v1' unless set to 'v2' here.
  # @option options [Integer] :timeout   Optional value for tuning HTTP timeouts. Default is 5 seconds.
  # @option options [Boolean] :fail_hard Optional Raise an exception on errors when true, or return an empty hash when false. (false)
  # @return [Hash] All key/value pairs from the given Vault path will be returned to hiera
  dispatch :vault_hiera_hash do
    param 'Hash', :options
    param 'Puppet::LookupContext', :context
  end

  require "#{File.dirname(__FILE__)}/../../puppet_x/vault_secrets/vaultsession.rb"
  require "json"

  def vault_hiera_hash(options, context)
    err_message = "The vault_hiera_hash function requires one of 'uri' or 'uris'"
    raise Puppet::DataBinding::LookupError, err_message unless options.key?('uri')

    Puppet.debug "Using Vault URL: #{options['uri']}"

    connection = {}

    # Hiera lookups, by default, should not fail hard when data is not found
    connection['fail_hard'] = false

    options.each do |key, value|
      connection[key] = value
    end

    if options.key?('token_file')
      token = File.read(options['token_file']).strip
      connection['token'] = token
    end

    # Use the Vault class for the lookup
    data = VaultSession.new(connection).get

    not_found = data.empty? || !data.is_a?(Hash)
    context.not_found if not_found
    unless not_found
      data.each do |key, value|
        begin
          data[key] = JSON.parse(value)
        rescue JSON::ParserError
        end
      end
    end
    context.cache_all(data)
    data
  end
end
