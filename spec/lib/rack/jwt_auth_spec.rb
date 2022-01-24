# frozen_string_literal: true

require 'spec_helper'
require 'jwt'

describe JWKAuth do
  let(:rsa_key_pair) { OpenSSL::PKey::RSA.new(2048) }
  # dummy app to validate success

  let(:inner_app) { ->(_env) { [200, {}, 'success'] } }

  let(:app) { JWKAuth.new(inner_app, { issuers_mapping: issuers_mapping }) }

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

  # add key so that JWK identifier can identify it
  let(:jwt_headers) do
    {
      kid: 'test'
    }
  end

  let(:jwt_payload_iss) { 'http://localhost:8000/' }

  let(:jwt_payload) do
    {
      sub: '1234567890',
      name: 'John Doe',
      iss: jwt_payload_iss,
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
  end

  context 'when invalid token is passed' do
    let(:jwt_token) do
      JWT.encode jwt_payload, OpenSSL::PKey::RSA.new(2048), 'RS256', jwt_headers
    end
    it 'returns unauthorized' do
      header 'Authorization', "Bearer malformed#{jwt_token}"
      get('/')
      expect(last_response.status).to eq 401
    end
  end

  context 'when excluded URL is not passed' do
    after(:each) do
      ENV['JWKS_EXCLUDES'] = nil
    end

    it 'uses health_check as default and allow health_check calls' do
      get('/health_check')
      expect(last_response.status).to eq 200
    end

    it 'fallback to JWKS_EXCLUDES env and allows it' do
      ENV['JWKS_EXCLUDES'] = '["/excludes"]'
      get('/excludes')
      expect(last_response.status).to eq 200
    end

    it 'fallback to JWKS_EXCLUDES env and block others' do
      ENV['JWKS_EXCLUDES'] = '["/excludes"]'
      get('/test_other')
      expect(last_response.status).to eq 401
    end

    it 'health_check is always allowed' do
      ENV['JWKS_EXCLUDES'] = '["/excludes"]'
      get('/health_check')
      expect(last_response.status).to eq 200
    end
  end

  context 'when exclude url is passed in options' do
    let(:app) do
      JWKAuth.new(
        inner_app,
        {
          issuers_mapping: issuers_mapping,
          excludes: ['/allowed_url']
        }
      )
    end
    it 'allows excluded urls' do
      get('/allowed_url')
      expect(last_response.status).to eq 200
    end
    it 'block other urls' do
      get('/denied_url')
      expect(last_response.status).to eq 401
    end
  end

  context 'when JWT signature does not match' do
    let(:jwt_token) do
      JWT.encode jwt_payload, OpenSSL::PKey::RSA.new(2048), 'RS256', jwt_headers
    end

    it 'returns unauthorized' do
      header 'Authorization', "Bearer #{jwt_token}"
      get('/')
      expect(last_response.status).to eq 401
    end
  end

  context 'when non RSA JWT is passed' do
    let(:jwt_token) do
      JWT.encode jwt_payload, 'hmac_secret', 'HS256', jwt_headers
    end

    it 'returns unauthorized' do
      header 'Authorization', "Bearer #{jwt_token}"
      get('/')
      expect(last_response.status).to eq 401
    end
  end

  context 'when issuer mapping is provided' do
    let(:issuers_mapping) do
      {
        first_iss: 'http://first.com/jwks',
        second_iss: 'http://second.com/jwks',
        Default: jwks_url
      }
    end

    let(:jwt_payload_iss) { 'first_iss' }

    let(:first_iss_rsa) { OpenSSL::PKey::RSA.new(2048) }
    let(:first_iss_jwk) { JWT::JWK.new(first_iss_rsa) }

    let(:second_iss_rsa) { OpenSSL::PKey::RSA.new(2048) }
    let(:second_iss_jwk) { JWT::JWK.new(second_iss_rsa) }

    before(:each) do
      stub_request(:get, 'http://first.com/jwks')
        .with(headers: { 'Accept' => '*/*', 'User-Agent' => 'Ruby' })
        .to_return(status: 200, body: { keys: [first_iss_jwk.export] }.to_json, headers: {})

      stub_request(:get, 'http://second.com/jwks')
        .with(headers: { 'Accept' => '*/*', 'User-Agent' => 'Ruby' })
        .to_return(status: 200, body: { keys: [second_iss_jwk.export] }.to_json, headers: {})
    end

    it 'uses a iss from the payload' do
      token = JWT.encode jwt_payload, first_iss_rsa, 'RS256', jwt_headers
      header 'Authorization', "Bearer #{token}"
      get('/')
      expect(last_response.status).to eq 200
    end

    it 'fallback to default if no matching' do
      payload = jwt_payload
      payload[:iss] = 'afjasfjasjfba'
      token = JWT.encode payload, rsa_key_pair, 'RS256', jwt_headers

      header 'Authorization', "Bearer #{token}"
      get('/')

      expect(last_response.status).to eq 200
    end

    it 'return 401 for the wrong iss' do
      token = JWT.encode jwt_payload, second_iss_rsa, 'RS256', jwt_headers
      header 'Authorization', "Bearer #{token}"
      get('/')
      expect(last_response.status).to eq 401
    end
  end
end
