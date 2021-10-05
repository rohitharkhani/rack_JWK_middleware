# frozen_string_literal: true

require 'uri'
require 'net/http'
require 'json'

module JWK
  class Verifier
    DEFAULT_ISSUER = :Default

    def initialize(issuer_certificate_mappings)
      @issuer_certificate_mappings = issuer_certificate_mappings
      @caheced_keys = {}
    end

    def validate(token)
      decoded_token = nil
      begin
        decoded_token = JWT.decode(token, nil, true, { algorithms: %w[RS512 RS256 RS384] }) do |header, payload|
          jwt_data = payload.merge(header)
          get_certificate(jwt_data)
        end
      rescue JWT::JWKError
        # TODO: stub rails logger for the unit test cases
        # Rails.logger.warn 'JWK errors'
      rescue JWT::DecodeError
        # TODO: stub rails logger for the unit test cases
        # Rails.logger.info 'Error in decoding JWT token'
      end
      # return nil at the end in case of the rescues and log it
      decoded_token
    end

    private

    def get_certificate(jwt_data)
      xt256 = jwt_data['xt#256']
      kid = jwt_data['kid']
      jwks = @caheced_keys[xt256] || @caheced_keys[kid]
      return jwks unless jwks.nil?

      url = get_url(jwt_data)
      jwk_key = get_keys(url)
      return null if jwk_key.nil?

      @caheced_keys[xt256 || kid] = jwk_key
      jwk_key
    end

    def get_url(jwt_data)
      issuer = jwt_data['iss']
      url_template = @issuer_certificate_mappings[issuer.to_sym] || @issuer_certificate_mappings[DEFAULT_ISSUER]
      return nil if url_template.nil?

      format(url_template, jwt_data)
    end

    def get_keys(url)
      response = reterive_keys(url)
      return if response.nil?

      decode_public_key(response)
    end

    def reterive_keys(url)
      uri = URI(url)
      res = Net::HTTP.get_response(uri)
      return unless res.is_a?(Net::HTTPSuccess)

      keys = JSON.parse(res.body, { symbolize_names: true })
      keys[:keys]
    end

    def decode_public_key(jwk_response)
      JWT::JWK.import(jwk_response.first).public_key
    end
  end
end
