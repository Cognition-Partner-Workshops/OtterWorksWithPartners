require 'rails_helper'

RSpec.describe Api::V1::Admin::ChaosController do
  let(:redis) { instance_double(Redis, setex: 'OK', keys: [], del: 0) }
  let(:chaos_secret) { 'test-chaos-secret' }
  let(:trigger_params) { { service: 'search-service', scenario: 'suggest_500' } }

  before do
    allow(Redis).to receive(:new).and_return(redis)
    allow(ChaosProbeService).to receive(:start)
  end

  around do |example|
    original = ENV.fetch('CHAOS_SECRET', nil)
    ENV['CHAOS_SECRET'] = chaos_secret
    example.run
  ensure
    ENV['CHAOS_SECRET'] = original
  end

  def authenticate(payload)
    request.env['jwt.payload'] = payload
  end

  context 'with an admin JWT and a valid chaos secret' do
    before do
      authenticate('sub' => 'u1', 'role' => 'super_admin')
      request.headers['X-Chaos-Secret'] = chaos_secret
    end

    it 'triggers the chaos scenario' do
      post :trigger, params: trigger_params
      expect(response).to have_http_status(:ok)
      expect(redis).to have_received(:setex).with('chaos:search-service:suggest_500', anything, '1')
    end

    it 'resets chaos flags' do
      delete :reset
      expect(response).to have_http_status(:ok)
    end
  end

  it 'accepts the auth-service roles claim' do
    authenticate('sub' => 'u1', 'roles' => ['ADMIN'])
    request.headers['X-Chaos-Secret'] = chaos_secret
    post :trigger, params: trigger_params
    expect(response).to have_http_status(:ok)
  end

  it 'rejects requests without a JWT payload' do
    request.headers['X-Chaos-Secret'] = chaos_secret
    post :trigger, params: trigger_params
    expect(response).to have_http_status(:forbidden)
    expect(redis).not_to have_received(:setex)
  end

  it 'rejects non-admin users' do
    authenticate('sub' => 'u1', 'role' => 'viewer', 'roles' => ['USER'])
    request.headers['X-Chaos-Secret'] = chaos_secret
    delete :reset
    expect(response).to have_http_status(:forbidden)
    expect(redis).not_to have_received(:keys)
  end

  it 'rejects an incorrect chaos secret' do
    authenticate('sub' => 'u1', 'role' => 'admin')
    request.headers['X-Chaos-Secret'] = 'wrong'
    post :trigger, params: trigger_params
    expect(response).to have_http_status(:unauthorized)
    expect(redis).not_to have_received(:setex)
  end

  context 'when CHAOS_SECRET is not configured' do
    let(:chaos_secret) { '' }

    it 'fails closed' do
      authenticate('sub' => 'u1', 'role' => 'super_admin')
      post :trigger, params: trigger_params
      expect(response).to have_http_status(:forbidden)
      expect(redis).not_to have_received(:setex)
      expect(ChaosProbeService).not_to have_received(:start)
    end
  end
end
