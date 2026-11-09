require 'rails_helper'

# End-to-end through JwtAuthenticator: a validly signed token is not enough,
# the caller must also carry an administrator role.
RSpec.describe 'Admin API authorization' do
  let!(:target) { create(:admin_user) }

  def json_put(path, headers:, body:)
    put path, params: body.to_json, headers: headers.merge('Content-Type' => 'application/json')
  end

  it 'rejects requests without a token' do
    get '/api/v1/admin/users'
    expect(response).to have_http_status(:unauthorized)
  end

  context 'with an auth-service token carrying roles [USER]' do
    let(:headers) { auth_headers(user_id: target.id, roles: %w[USER]) }

    it 'returns 403 on GET /api/v1/admin/users' do
      get '/api/v1/admin/users', headers: headers
      expect(response).to have_http_status(:forbidden)
      expect(response.parsed_body['error']).to match(/administrator role required/)
    end

    it 'returns 403 when the user tries to promote themselves to super_admin' do
      json_put "/api/v1/admin/users/#{target.id}", headers: headers, body: { user: { role: 'super_admin' } }
      expect(response).to have_http_status(:forbidden)
      expect(target.reload.role).to eq('viewer')
    end

    it 'returns 403 on the other admin controllers' do
      get '/api/v1/admin/features', headers: headers
      expect(response).to have_http_status(:forbidden)
      get '/api/v1/admin/audit-logs', headers: headers
      expect(response).to have_http_status(:forbidden)
      get '/api/v1/admin/settings/auto_investigate', headers: headers
      expect(response).to have_http_status(:forbidden)
    end
  end

  context 'with an auth-service token carrying roles [ADMIN]' do
    let(:headers) { auth_headers(roles: %w[USER ADMIN]) }

    it 'returns 200 on GET /api/v1/admin/users' do
      get '/api/v1/admin/users', headers: headers
      expect(response).to have_http_status(:ok)
      expect(response.parsed_body['users'].pluck('id')).to include(target.id)
    end

    it 'returns 403 when assigning the super_admin role' do
      json_put "/api/v1/admin/users/#{target.id}", headers: headers, body: { user: { role: 'super_admin' } }
      expect(response).to have_http_status(:forbidden)
      expect(target.reload.role).to eq('viewer')
    end
  end

  context 'with a legacy token carrying role=super_admin' do
    let(:headers) { auth_headers(role: 'super_admin') }

    it 'can assign the super_admin role' do
      json_put "/api/v1/admin/users/#{target.id}", headers: headers, body: { user: { role: 'super_admin' } }
      expect(response).to have_http_status(:ok)
      expect(target.reload.role).to eq('super_admin')
    end
  end

  it 'leaves the unauthenticated health endpoint reachable' do
    get '/health'
    expect(response).to have_http_status(:ok)
  end
end
