# frozen_string_literal: true

require 'puppet'
require 'uri'
require 'openssl'
require 'json'

# Class provides methods to interface with Hashicorp Vault
class VaultSession
  def initialize(args)
    # @summary Provide methods to interface with Hashicorp Vault
    # @param [Hash] args Configuration options for the Vault connection.
    # @option args [String] :uri Required The URL of a Vault API endpoint
    # @option args [Integer] :timeout Optional Seconds to wait for connection attempts. (5)
    # @option args [Boolean] :secure Optional When true, security certificates will be validated against the 'ca_file' (true)
    # @option args [String] :ca_file Optional path to a file containing the trusted certificate authority chain.
    # @option args [String] :token Optional token used to access the Vault API, otherwise attempts certificate authentication using the Puppet agent certificate.
    # @option args [String] :auth_path The Vault path of the "cert" authentication type for Puppet certificates
    # @option args [String] :auth_name The optional Vault certificate named role to authenticate against
    # @option args [Boolean] :fail_hard Optional Raise an exception on errors when true, or return an empty hash when false. (true)
    # @option args [String] :version The version of the Vault key/value secrets engine, either 'v1' or 'v2'. (v1)

    Puppet.debug "VaultSession: initializing with args keys: #{args.keys.inspect}"
    Puppet.debug "VaultSession: uri=#{args['uri'].inspect}, ca_trust=#{args['ca_trust'].inspect}, " \
                 "auth_path=#{args['auth_path'].inspect}, token=#{args.key?('token') ? '[PRESENT]' : '[ABSENT]'}, " \
                 "token_file=#{args['token_file'].inspect}, secure=#{args['secure'].inspect}, " \
                 "timeout=#{args['timeout'].inspect}, version=#{args['version'].inspect}, " \
                 "fail_hard=#{args['fail_hard'].inspect}"

    raise Puppet::Error, "The #{self.class.name} class requires a 'uri'." unless args.key?('uri')
    @uri = URI(args['uri'])
    raise Puppet::Error, "Unable to parse a hostname from #{args['uri']}" unless uri.hostname
    @fail_hard = if [true, false].include? args.dig('fail_hard')
                   args.dig('fail_hard')
                 else
                   true
                 end
    timeout = if args.dig('timeout').is_a? Integer
                args['timeout']
              else
                5
              end
    @version = if args.dig('version') == 'v2'
                 'v2'
               else
                 'v1'
               end
    http = Net::HTTP.new(uri.host, uri.port)
    http.open_timeout = timeout
    http.read_timeout = timeout
    secure = true unless args.dig('secure') == false || @uri.scheme == 'http'
    Puppet.debug "VaultSession: secure=#{secure.inspect}, scheme=#{@uri.scheme}"
    if secure
      ca_trust = if args.dig('ca_trust').is_a? String
                   args['ca_trust']
                 else
                   nil
                 end
      Puppet.debug "VaultSession: configuring SSL with ca_trust=#{ca_trust.inspect}"
      http.use_ssl = true
      http.ssl_version = :TLSv1_2
      http.cert_store = get_cert_store(ca_trust)
      http.verify_mode = OpenSSL::SSL::VERIFY_PEER
      Puppet.debug "VaultSession: SSL configured — verify_mode=VERIFY_PEER, ssl_version=TLSv1_2"
    elsif @uri.scheme == 'https'
      Puppet.debug "VaultSession: SSL enabled but verification DISABLED (secure=false)"
      http.use_ssl = true
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    else
      Puppet.debug "VaultSession: SSL disabled (scheme=#{@uri.scheme})"
      http.use_ssl = false
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    end
    @http = http
    token = if args.dig('token')
              Puppet.debug "VaultSession: using pre-supplied token for auth"
              args['token']
            else
              raise Puppet::Error, "An 'auth_path' must be defined when not using a token." unless args.key?('auth_path')
              Puppet.debug "VaultSession: authenticating via Puppet certificate at auth_path=#{args['auth_path'].inspect}"
              get_token(args['auth_path'], args['auth_name'])
            end
    @headers = {
      'Content-Type': 'application/json',
      'X-Vault-Token': token,
    }
    Puppet.debug "VaultSession: initialization complete for #{@uri}"
  end

  attr_accessor :uri, :http, :secure, :fail_hard

  def err_check(response)
    # @summary Consistent error handling for common failures
    # @param response An instance of Net::HTTPResponse
    # @return nil
    if response.is_a?(Net::HTTPNotFound)
      err_message = "Vault path not found. (#{response.code} from #{@uri})"
      raise Puppet::Error, append_api_errors(err_message, response) if fail_hard
      Puppet.debug append_api_errors(err_message, response)
    elsif !response.is_a?(Net::HTTPOK)
      err_message = "Vault request failed. (#{response.code}) from #{@uri})"
      raise Puppet::Error, append_api_errors(err_message, response) if fail_hard
      Puppet.debug append_api_errors(err_message, response)
    end
    nil
  end

  def append_api_errors(message, response)
    # @summary Add meaningful(maybe?) messages to errors
    # @param [String] :message The error string before appending any API errors.
    # @param [Net::HTTPResponse] :response The method will try to read errors from the response and append to 'message'
    # @return [String] The updated error message including any errors found in the response.
    errors = begin
               JSON.parse_json(response.body)['errors']
             rescue
               nil
             end
    message << " (api errors: #{errors})" if errors
    message
  end

  def parse_response(response, version = @version)
    # @summary Process an HTTP response as a JSON string and return Vault secrets
    # @param [Net::HTTPResponse] :response The object body will be parsed as JSON.
    # @param [String] :version The version of the Vault key/value secrets engine in the response, either 'v1' or 'v2' (v1)
    # @return [Hash] The returned hash contains the secret key/value pairs.
    begin
      output = if version == 'v2'
                 JSON.parse(response.body)['data']['data']
               else
                 JSON.parse(response.body)['data']
               end
    rescue
      nil
    end
    err_message = "Failed to parse #{version} key/value data from response body: (#{@uri_path})"
    raise Puppet::Error, err_message if output.nil? && fail_hard
    Puppet.debug err_message if output.nil?
    output ||= {}
    v1_warn = "Data from '#{@uri_path}' was requested as key/value v2, but may be v1 or just be empty."
    Puppet.debug v1_warn if @version == 'v2' &&  output.empty?
    v2_warn = "Data from '#{@uri_path}' appears to be key/value v2, but was requested as v1"
    Puppet.debug v2_warn if @version == 'v1' &&  output.dig('data') && output.dig('metadata')
    output
  end

  def get(uri_path = @uri.path, version = @version)
    # @summary Submit an HTTP GET request to the given 'uri_path'
    # @param [String] :uri_path A relative path component of a URI, or reference URI.path
    # @param [String] :version The version of the Vault key/value secrets engine (v1)
    # @retrun [Hash] A hash containing the secret key/value pairs.
    @uri_path = uri_path
    Puppet.debug "VaultSession GET: #{@uri.host}:#{@uri.port}#{uri_path} (version=#{version})"
    request = Net::HTTP::Get.new(uri_path)
    @headers.each do |key, value|
      request[key] = value
    end
    begin
      response = http.request(request)
    rescue OpenSSL::SSL::SSLError => e
      Puppet.err "VaultSession GET: SSL ERROR connecting to #{@uri.host}:#{@uri.port} — #{e.class}: #{e.message}"
      Puppet.err "VaultSession GET: SSL error backtrace:\n  #{e.backtrace.first(10).join("\n  ")}"
      debug_ssl_connection_error
      raise
    rescue => e
      Puppet.err "VaultSession GET: connection error to #{@uri.host}:#{@uri.port} — #{e.class}: #{e.message}"
      raise
    end
    Puppet.debug "VaultSession GET: response #{response.code} #{response.message}"
    err_check(response)
    parse_response(response, version)
  end

  def post(uri_path = @uri.path, data = {})
    # @summary Submit an http post request to the given 'uri_path'
    # @param [String] :uri_path A relative path component of a URI, or reference to a URI.path.
    # @param [Hash] :data A hash of values to submit with the HTTP POST request.
    # return [Net::HTTPResponse]
    @uri_path = uri_path
    Puppet.debug "VaultSession POST: #{@uri.host}:#{@uri.port}#{uri_path}"
    request = Net::HTTP::Post.new(uri_path)
    # This function may be called before instance variable is defined as part of initialize
    @headers ||=  {}
    @headers.each do |key, value|
      request[key] = value
    end
    request.body = data.to_json
    begin
      response = http.request(request)
    rescue OpenSSL::SSL::SSLError => e
      Puppet.err "VaultSession POST: SSL ERROR connecting to #{@uri.host}:#{@uri.port} — #{e.class}: #{e.message}"
      Puppet.err "VaultSession POST: SSL error backtrace:\n  #{e.backtrace.first(10).join("\n  ")}"
      debug_ssl_connection_error
      raise
    rescue => e
      Puppet.err "VaultSession POST: connection error to #{@uri.host}:#{@uri.port} — #{e.class}: #{e.message}"
      raise
    end
    Puppet.debug "VaultSession POST: response #{response.code} #{response.message}"
    err_check(response)
    response
  end

  def get_token(auth_path, auth_name)
    # @summary Use the Puppet host certificate and private key to authenticate to Vault
    # @param [String] :auth_path The Vault path of the "cert" authentication type for Puppet
    # @param [String] :auth_name The optional Vault named certificate role to authenticate against
    # @return [String] A Vault token.

    # Get the client certificate and private key files for Vault authenticaion
    hostcert = File.expand_path(Puppet.settings[:hostcert])
    hostprivkey = File.expand_path(Puppet.settings[:hostprivkey])
    Puppet.debug "VaultSession get_token: hostcert=#{hostcert}, hostprivkey=#{hostprivkey}"
    Puppet.debug "VaultSession get_token: hostcert exists=#{File.exist?(hostcert)}, hostprivkey exists=#{File.exist?(hostprivkey)}"

    begin
      cert_content = File.read(hostcert)
      http.cert = OpenSSL::X509::Certificate.new(cert_content)
      Puppet.debug "VaultSession get_token: client cert subject=#{http.cert.subject}, issuer=#{http.cert.issuer}"
      Puppet.debug "VaultSession get_token: client cert serial=#{http.cert.serial}, not_after=#{http.cert.not_after}"
    rescue => e
      Puppet.err "VaultSession get_token: failed to load client cert from #{hostcert} — #{e.class}: #{e.message}"
      raise
    end

    begin
      http.key = OpenSSL::PKey::RSA.new(File.read(hostprivkey))
      Puppet.debug "VaultSession get_token: client private key loaded successfully"
    rescue => e
      Puppet.err "VaultSession get_token: failed to load private key from #{hostprivkey} — #{e.class}: #{e.message}"
      raise
    end

    data = auth_name ? { name: auth_name } : nil
    Puppet.debug "VaultSession get_token: authenticating at /v1/auth/#{auth_path.gsub(%r{/$}, '')}/login (auth_name=#{auth_name.inspect})"

    # Submit the request to the auth_path login endpoint
    response = post("/v1/auth/#{auth_path.gsub(%r{/$}, '')}/login", data)
    err_check(response)

    # Extract the token value from the response
    begin
      token = JSON.parse(response.body)['auth']['client_token']
    rescue
      raise Puppet::Error, 'Unable to parse client_token from vault response.'
    end
    raise Puppet::Error, 'No client_token found.' if token.nil?
    Puppet.debug "VaultSession get_token: successfully obtained token"
    token
  end

  def get_cert_store(ca_trust)
    # @summary Initialize an X509 Store and load CA certificates for verification
    # @param [String] ca_trust The path to a trusted certificate authority file.
    # @return [OpenSSL::X509::Store] An SSL certificate store with the CA loaded.
    Puppet.debug "VaultSession get_cert_store: called with ca_trust=#{ca_trust.inspect}"
    Puppet.debug "VaultSession get_cert_store: OpenSSL version=#{OpenSSL::OPENSSL_VERSION}, " \
                 "library version=#{OpenSSL::OPENSSL_LIBRARY_VERSION rescue 'N/A'}"
    Puppet.debug "VaultSession get_cert_store: OpenSSL default cert file=#{OpenSSL::X509::DEFAULT_CERT_FILE rescue 'N/A'}, " \
                 "default cert dir=#{OpenSSL::X509::DEFAULT_CERT_DIR rescue 'N/A'}"

    store = OpenSSL::X509::Store.new

    files_to_load = []

    if ca_trust && File.exist?(ca_trust)
      Puppet.debug "VaultSession get_cert_store: using user-specified ca_trust file: #{ca_trust}"
      Puppet.debug "VaultSession get_cert_store: ca_trust file size=#{File.size(ca_trust)} bytes, " \
                   "readable=#{File.readable?(ca_trust)}, mtime=#{File.mtime(ca_trust)}"
      files_to_load << ca_trust
    elsif ca_trust
      Puppet.warning "VaultSession get_cert_store: ca_trust was specified as '#{ca_trust}' but the file does NOT exist!"
      Puppet.debug "VaultSession get_cert_store: falling through to system bundle detection"
    end

    unless ca_trust && File.exist?(ca_trust)
      sys_bundles = [
        '/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem', # RHEL/CentOS
        '/etc/ssl/certs/ca-certificates.crt',                # Debian/Ubuntu
        '/etc/ssl/cert.pem'                                  # Alpine/General
      ]
      sys_bundles.each do |sys_file|
        exists = File.exist?(sys_file)
        Puppet.debug "VaultSession get_cert_store: system bundle #{sys_file} exists=#{exists}" \
                     "#{exists ? ", size=#{File.size(sys_file)} bytes" : ''}"
        files_to_load << sys_file if exists
      end
    end

    # Fall back to OpenSSL defaults only when no bundle files were found
    if files_to_load.empty?
      Puppet.warning "VaultSession get_cert_store: NO bundle files found — falling back to OpenSSL set_default_paths"
      Puppet.debug "VaultSession get_cert_store: set_default_paths will use cert_file=#{OpenSSL::X509::DEFAULT_CERT_FILE rescue 'N/A'}, " \
                   "cert_dir=#{OpenSSL::X509::DEFAULT_CERT_DIR rescue 'N/A'}"
      store.set_default_paths
      return store
    end

    Puppet.debug "VaultSession get_cert_store: will load certificates from #{files_to_load.length} file(s): #{files_to_load.inspect}"

    total_certs_loaded = 0
    total_duplicates = 0
    total_malformed = 0

    files_to_load.uniq.each do |file_path|
      begin
        content = File.read(file_path)
        pem_blocks = content.scan(/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/m)
        Puppet.debug "VaultSession get_cert_store: file #{file_path} contains #{pem_blocks.length} PEM certificate(s)"

        pem_blocks.each_with_index do |cert_pem, idx|
          begin
            cert = OpenSSL::X509::Certificate.new(cert_pem)
            store.add_cert(cert)
            total_certs_loaded += 1
            # Log first few and last cert for debugging without flooding
            if idx < 3 || idx == pem_blocks.length - 1
              Puppet.debug "VaultSession get_cert_store:   [#{idx}] loaded: subject=#{cert.subject}, " \
                           "issuer=#{cert.issuer}, not_after=#{cert.not_after}"
            elsif idx == 3
              Puppet.debug "VaultSession get_cert_store:   ... (skipping detailed log for middle certs) ..."
            end
          rescue OpenSSL::X509::StoreError
            total_duplicates += 1
          rescue OpenSSL::X509::CertificateError => e
            total_malformed += 1
            Puppet.debug "VaultSession get_cert_store:   [#{idx}] MALFORMED cert skipped: #{e.message}"
          end
        end
      rescue => e
        Puppet.warning "VaultSession: Failed to read #{file_path}: #{e.message}"
      end
    end

    Puppet.debug "VaultSession get_cert_store: SUMMARY — loaded=#{total_certs_loaded}, " \
                 "duplicates_skipped=#{total_duplicates}, malformed_skipped=#{total_malformed}"

    store
  end

  def debug_ssl_connection_error
    # @summary Log detailed SSL diagnostic information when a connection fails
    Puppet.err "VaultSession SSL DIAGNOSTICS:"
    Puppet.err "  Target: #{@uri.host}:#{@uri.port}"
    Puppet.err "  OpenSSL version: #{OpenSSL::OPENSSL_VERSION}"
    Puppet.err "  OpenSSL library version: #{OpenSSL::OPENSSL_LIBRARY_VERSION rescue 'N/A'}"
    Puppet.err "  Ruby version: #{RUBY_VERSION} (#{RUBY_PLATFORM})"
    Puppet.err "  http.use_ssl=#{http.use_ssl?}, http.verify_mode=#{http.verify_mode}"
    Puppet.err "  http.ssl_version=#{http.ssl_version rescue 'N/A'}"
    Puppet.err "  http.ca_file=#{http.ca_file.inspect}"
    Puppet.err "  http.ca_path=#{http.ca_path.inspect}"
    Puppet.err "  http.cert_store set=#{!http.cert_store.nil?}"
    if http.cert
      Puppet.err "  http.cert (client) subject=#{http.cert.subject}, issuer=#{http.cert.issuer}"
    else
      Puppet.err "  http.cert (client) = nil"
    end

    # Attempt a raw OpenSSL connection to get the server's certificate chain
    begin
      Puppet.err "  Attempting raw OpenSSL probe of #{@uri.host}:#{@uri.port} ..."
      tcp = TCPSocket.new(@uri.host, @uri.port)
      ssl_ctx = OpenSSL::SSL::SSLContext.new
      ssl_ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
      ssl_sock = OpenSSL::SSL::SSLSocket.new(tcp, ssl_ctx)
      ssl_sock.hostname = @uri.host
      ssl_sock.connect
      peer_cert = ssl_sock.peer_cert
      peer_chain = ssl_sock.peer_cert_chain
      Puppet.err "  Server certificate subject: #{peer_cert.subject}"
      Puppet.err "  Server certificate issuer:  #{peer_cert.issuer}"
      Puppet.err "  Server certificate serial:  #{peer_cert.serial}"
      Puppet.err "  Server certificate not_before: #{peer_cert.not_before}"
      Puppet.err "  Server certificate not_after:  #{peer_cert.not_after}"

      san_ext = peer_cert.extensions.find { |e| e.oid == 'subjectAltName' }
      Puppet.err "  Server certificate SANs: #{san_ext ? san_ext.value : 'NONE'}"

      if peer_chain
        Puppet.err "  Server presented #{peer_chain.length} certificate(s) in chain:"
        peer_chain.each_with_index do |c, i|
          Puppet.err "    [#{i}] subject=#{c.subject}, issuer=#{c.issuer}, not_after=#{c.not_after}"
        end
      else
        Puppet.err "  Server presented NO certificate chain"
      end

      # Now try to verify the chain with our cert store
      if http.cert_store
        Puppet.err "  Attempting manual verification of server cert against our cert_store..."
        store_ctx = OpenSSL::X509::StoreContext.new(http.cert_store, peer_cert, peer_chain || [])
        verified = store_ctx.verify
        Puppet.err "  Manual verification result: #{verified}"
        unless verified
          Puppet.err "  Verification error: #{store_ctx.error} — #{store_ctx.error_string}"
          Puppet.err "  Error depth: #{store_ctx.error_depth}"
          if store_ctx.current_cert
            Puppet.err "  Cert at error depth: subject=#{store_ctx.current_cert.subject}, issuer=#{store_ctx.current_cert.issuer}"
          end
        end
      end

      ssl_sock.close
      tcp.close
    rescue => probe_err
      Puppet.err "  SSL probe failed: #{probe_err.class}: #{probe_err.message}"
      Puppet.err "  SSL probe backtrace:\n    #{probe_err.backtrace.first(5).join("\n    ")}"
    end
  end

end
