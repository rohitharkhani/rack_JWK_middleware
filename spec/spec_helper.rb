# frozen_string_literal: true

require 'simplecov'
SimpleCov.start do
  add_filter 'spec/'
end

require 'rspec'
require 'webmock/rspec'
require 'rack/test'
require_relative '../lib/rack/jwk_auth'

RSpec.configure do |conf|
  conf.include Rack::Test::Methods
end
