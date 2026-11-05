require 'rails_helper'

RSpec.describe JwtAuthenticator do
  let(:downstream) { ->(_env) { [200, {}, ['ok']] } }
  let(:middleware) { described_class.new(downstream) }

  it 'requires a JWT for the chaos endpoint' do
    status, = middleware.call(Rack::MockRequest.env_for('/api/v1/admin/chaos', method: 'POST'))
    expect(status).to eq(401)
  end

  it 'still skips authentication for health checks' do
    status, = middleware.call(Rack::MockRequest.env_for('/health'))
    expect(status).to eq(200)
  end
end
