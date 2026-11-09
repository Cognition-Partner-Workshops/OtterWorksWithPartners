require 'rails_helper'

RSpec.describe Api::V1::Admin::BulkController do
  before { set_jwt_env(request) }

  describe 'POST #users' do
    let!(:users) { create_list(:admin_user, 3) }
    let(:user_ids) { users.map(&:id) }

    it 'suspends multiple users' do
      post :users, params: { operation: 'suspend', user_ids: user_ids, reason: 'Policy' }
      expect(response).to have_http_status(:ok)
      body = JSON.parse(response.body)
      expect(body['success_count']).to eq(3)
      expect(body['failure_count']).to eq(0)
    end

    it 'activates multiple users' do
      users.each(&:suspend!)
      post :users, params: { operation: 'activate', user_ids: user_ids }
      expect(response).to have_http_status(:ok)
      body = JSON.parse(response.body)
      expect(body['success_count']).to eq(3)
    end

    context 'when the caller is an admin (not super_admin)' do
      before { set_jwt_env(request, role: 'admin') }

      it 'can suspend users' do
        post :users, params: { operation: 'suspend', user_ids: user_ids, reason: 'Policy' }
        expect(response).to have_http_status(:ok)
      end

      it 'can assign a non-privileged role' do
        post :users, params: { operation: 'update_role', user_ids: user_ids, role: 'editor' }
        expect(response).to have_http_status(:ok)
        expect(users.map { |u| u.reload.role }).to all(eq('editor'))
      end

      it 'cannot grant the super_admin role' do
        post :users, params: { operation: 'update_role', user_ids: user_ids, role: 'super_admin' }
        expect(response).to have_http_status(:forbidden)
        expect(users.map { |u| u.reload.role }).to all(eq('viewer'))
      end

      it 'cannot demote a super_admin' do
        target = create(:admin_user, :super_admin)
        post :users, params: { operation: 'update_role', user_ids: [target.id], role: 'viewer' }
        expect(response).to have_http_status(:forbidden)
        expect(target.reload.role).to eq('super_admin')
      end
    end

    it 'forbids non-admin callers' do
      set_jwt_env(request, role: 'viewer')
      post :users, params: { operation: 'suspend', user_ids: user_ids }
      expect(response).to have_http_status(:forbidden)
    end

    it 'returns multi_status when some users not found' do
      post :users, params: { operation: 'suspend', user_ids: user_ids + [SecureRandom.uuid] }
      expect(response).to have_http_status(:multi_status)
      body = JSON.parse(response.body)
      expect(body['failure_count']).to eq(1)
    end

    it 'returns bad_request for empty user_ids' do
      post :users, params: { operation: 'suspend', user_ids: [] }
      expect(response).to have_http_status(:bad_request)
    end
  end
end
