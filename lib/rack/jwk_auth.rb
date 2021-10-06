# frozen_string_literal: true

require_relative '../jwk_verifier'
class JWKAuth
  # The last segment gets dropped for 'none' algorithm since there is no
  # signature so both of these patterns are valid. All character chunks
  # are base64url format and periods.
  #   Bearer abc123.abc123.abc123
  #   Bearer abc123.abc123.
  BEARER_TOKEN_REGEX = /
    ^Bearer\s{1}(       # starts with Bearer and a single space
    [a-zA-Z0-9\-_]+\.  # 1 or more chars followed by a single period
    [a-zA-Z0-9\-_]+\.  # 1 or more chars followed by a single period
    [a-zA-Z0-9\-_]*    # 0 or more chars, no trailing chars
    )$
  /x.freeze

  def initialize(app, opts)
    @app = app

    initialize_excludes(opts[:excludes])
    initialize_issuer(opts[:issuers_mapping])

    raise ArgumentError, 'Issuers mapping not provided' if @issuer.nil?

    @jwk_verifier = JWK::Verifier.new(@issuer)
  end

  def initialize_excludes(excludes)
    # default is /health_check
    @exclude = ['/health_check']
    if excludes.nil?
      @exclude = JSON.parse(ENV['JWKS_EXCLUDES']) unless ENV['JWKS_EXCLUDES'].nil?
    else
      @exclude = excludes
    end
  end

  def initialize_issuer(issuers)
    # try to parse JWKS_ISSUER_MAPPING env variable if it is not passed as arguments
    if issuers.nil?
      @issuer = JSON.parse(ENV['JWKS_ISSUER_MAPPING']) unless ENV['JWKS_ISSUER_MAPPING'].nil?
    else
      @issuer = issuers
    end
  end

  def call(env)
    if path_matches_excluded_path?(env)
      @app.call(env)
    elsif missing_auth_header?(env)
      return_error('Missing Authorization header')
    else
      verify_token(env)
    end
  end

  private

  def verify_token(env)
    token = BEARER_TOKEN_REGEX.match(env['HTTP_AUTHORIZATION'])[1]
    decoded_token = @jwk_verifier.validate(token)
    return return_error('Invalid JWK Token') if decoded_token.nil?

    env['jwk.payload'] = decoded_token.first
    env['jwk.header'] = decoded_token.last
    @app.call(env)
  end

  def missing_auth_header?(env)
    env['HTTP_AUTHORIZATION'].nil? || env['HTTP_AUTHORIZATION'].strip.empty?
  end

  def path_matches_excluded_path?(env)
    @exclude.any? { |ex| env['PATH_INFO'].start_with?(ex) }
  end

  def return_error(message)
    body    = { error: message }.to_json
    headers = { 'Content-Type' => 'application/json' }

    [401, headers, [body]]
  end
end
