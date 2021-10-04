# frozen_string_literal: true

require 'spec_helper'
require 'jwt'

describe JWTKAuth do
  let(:rsa_key_pair) { OpenSSL::PKey::RSA.new(2048) }
  # dummy app to validate success

  let(:inner_app) { ->(_env) { [200, {}, 'success'] } }
  let(:app) { JWTKAuth.new(inner_app, { issuers_mapping: issuers_mapping }) }

  let(:jwk) do
    JWT::JWK.new(rsa_key_pair)
  end

  let(:jwks_url) do
    'http://lcalhost:8080/jwks'
  end

  let(:jwks_response) do
    {
      keys: [
        jwk.export
      ]
    }
  end

  before(:each) do
    stub_request(:get, jwks_url)
      .with(headers: { 'Accept' => '*/*', 'User-Agent' => 'Ruby' })
      .to_return(status: 200, body: jwks_response.to_json, headers: {})
  end

  let(:issuers_mapping) do
    { Default: jwks_url }
  end

  let(:jwt_token_key_pair) { jwk }

  # add key so that JWK identifier can identify it
  let(:jwt_headers) do
    {
      kid: 'test'
    }
  end

  let(:jwt_payload) do
    {
      sub: '1234567890',
      name: 'John Doe',
      iss: 'http://localhost:8000/',
      admin: true,
      iat: 1_516_239_022
    }
  end

  let(:jwt_token) do
    JWT.encode jwt_payload, rsa_key_pair, 'RS256', jwt_headers
  end

  context 'when valid token is passed' do
    it 'succeeds' do
      header 'Authorization', "Bearer #{jwt_token}"
      get('/')
      expect(last_response.status).to eq 200
    end
    it 'attach header to context' do
    end

    it 'attach payload to context' do
    end
  end

  context 'when invalid token is passed' do
  end

  context 'When whitelist is configured' do
  end

  context 'when signed with different key' do
    let(:jwt_token) do
      JWT.encode jwt_payload, OpenSSL::PKey::RSA.new(2048), 'RS256', jwt_headers
    end
    it 'returns unauthorised' do
      header 'Authorization', "Bearer #{jwt_token}"
      get('/')
      expect(last_response.status).to eq 401
    end
  end
end
