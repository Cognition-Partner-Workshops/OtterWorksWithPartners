require 'rails_helper'

RSpec.describe Api::V1::Admin::UsersController do
  before { set_jwt_env(request) }

  describe 'authorization' do
    let!(:user) { create(:admin_user) }

    %w[viewer editor user].each do |role|
      context "when the token carries the #{role} role" do
        before { set_jwt_env(request, role: role) }

        it 'forbids listing users' do
          get :index
          expect(response).to have_http_status(:forbidden)
          expect(JSON.parse(response.body)['error']).to match(/administrator role required/)
        end

        it 'forbids self-promotion to super_admin' do
          put :update, params: { id: user.id, user: { role: 'super_admin' } }
          expect(response).to have_http_status(:forbidden)
          expect(user.reload.role).to eq('viewer')
        end

        it 'forbids suspending and deleting users' do
          put :suspend, params: { id: user.id }
          expect(response).to have_http_status(:forbidden)
          delete :destroy, params: { id: user.id }
          expect(response).to have_http_status(:forbidden)
          expect(user.reload.status).to eq('active')
        end
      end
    end

    context 'when the request carries no role information' do
      before { set_jwt_env(request, role: nil, roles: []) }

      it 'forbids access' do
        get :index
        expect(response).to have_http_status(:forbidden)
      end
    end

    context 'when the token carries an auth-service roles array' do
      it 'allows ADMIN' do
        set_jwt_env(request, roles: %w[USER ADMIN])
        get :index
        expect(response).to have_http_status(:ok)
      end

      it 'allows OWNER' do
        set_jwt_env(request, roles: %w[OWNER])
        get :index
        expect(response).to have_http_status(:ok)
      end

      it 'forbids USER' do
        set_jwt_env(request, roles: %w[USER])
        get :index
        expect(response).to have_http_status(:forbidden)
      end
    end
  end

  describe 'GET #index' do
    let!(:users) { create_list(:admin_user, 3) }

    it 'returns paginated user list' do
      get :index
      expect(response).to have_http_status(:ok)
      body = JSON.parse(response.body)
      expect(body['users'].length).to eq(3)
      expect(body['total']).to eq(3)
    end

    it 'filters by role' do
      create(:admin_user, :admin)
      get :index, params: { role: 'admin' }
      body = JSON.parse(response.body)
      expect(body['users'].all? { |u| u['role'] == 'admin' }).to be true
    end

    it 'filters by status' do
      create(:admin_user, :suspended)
      get :index, params: { status: 'suspended' }
      body = JSON.parse(response.body)
      expect(body['users'].all? { |u| u['status'] == 'suspended' }).to be true
    end

    it 'searches by query' do
      user = create(:admin_user, email: 'searchable@test.com')
      get :index, params: { q: 'searchable' }
      body = JSON.parse(response.body)
      expect(body['users'].any? { |u| u['id'] == user.id }).to be true
    end
  end

  describe 'GET #show' do
    let(:user) { create(:admin_user) }

    it 'returns user details' do
      get :show, params: { id: user.id }
      expect(response).to have_http_status(:ok)
      body = JSON.parse(response.body)
      expect(body['id']).to eq(user.id)
      expect(body['email']).to eq(user.email)
    end

    it 'returns 404 for missing user' do
      get :show, params: { id: SecureRandom.uuid }
      expect(response).to have_http_status(:not_found)
    end
  end

  describe 'PUT #update' do
    let(:user) { create(:admin_user) }

    it 'updates user attributes' do
      put :update, params: { id: user.id, user: { display_name: 'New Name' } }
      expect(response).to have_http_status(:ok)
      body = JSON.parse(response.body)
      expect(body['display_name']).to eq('New Name')
    end

    it 'returns errors for invalid params' do
      put :update, params: { id: user.id, user: { role: 'invalid_role' } }
      expect(response).to have_http_status(:unprocessable_entity)
    end

    it 'lets a super_admin grant the super_admin role' do
      put :update, params: { id: user.id, user: { role: 'super_admin' } }
      expect(response).to have_http_status(:ok)
      expect(user.reload.role).to eq('super_admin')
    end

    context 'when the caller is an admin (not super_admin)' do
      before { set_jwt_env(request, role: 'admin') }

      it 'can update non-role attributes' do
        put :update, params: { id: user.id, user: { display_name: 'Renamed' } }
        expect(response).to have_http_status(:ok)
      end

      it 'can assign a non-privileged role' do
        put :update, params: { id: user.id, user: { role: 'editor' } }
        expect(response).to have_http_status(:ok)
        expect(user.reload.role).to eq('editor')
      end

      %w[admin super_admin].each do |privileged_role|
        it "cannot grant the #{privileged_role} role" do
          put :update, params: { id: user.id, user: { role: privileged_role } }
          expect(response).to have_http_status(:forbidden)
          expect(user.reload.role).to eq('viewer')
        end
      end

      it 'cannot demote a super_admin' do
        target = create(:admin_user, :super_admin)
        put :update, params: { id: target.id, user: { role: 'viewer' } }
        expect(response).to have_http_status(:forbidden)
        expect(target.reload.role).to eq('super_admin')
      end
    end
  end

  describe 'DELETE #destroy' do
    let(:user) { create(:admin_user) }

    it 'soft-deletes the user' do
      delete :destroy, params: { id: user.id }
      expect(response).to have_http_status(:no_content)
      expect(user.reload.status).to eq('deleted')
    end
  end

  describe 'PUT #suspend' do
    let(:user) { create(:admin_user) }

    it 'suspends the user' do
      put :suspend, params: { id: user.id, reason: 'Policy violation' }
      expect(response).to have_http_status(:ok)
      body = JSON.parse(response.body)
      expect(body['status']).to eq('suspended')
    end
  end

  describe 'PUT #activate' do
    let(:user) { create(:admin_user, :suspended) }

    it 'activates the user' do
      put :activate, params: { id: user.id }
      expect(response).to have_http_status(:ok)
      body = JSON.parse(response.body)
      expect(body['status']).to eq('active')
    end
  end
end
