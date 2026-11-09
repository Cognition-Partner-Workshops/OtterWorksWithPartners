class ApplicationController < ActionController::API
  # Roles accepted by the admin API. The admin-service's own AdminUser roles are
  # lowercase (super_admin/admin); the auth-service issues uppercase enum names
  # (ADMIN/OWNER) in a `roles` array, which JwtAuthenticator downcases.
  SUPER_ADMIN_ROLES = %w[super_admin owner].freeze
  ADMIN_ROLES = (SUPER_ADMIN_ROLES + %w[admin]).freeze

  before_action :set_request_metadata
  before_action :require_admin!

  rescue_from StandardError do |e|
    Rails.logger.error("Unhandled error: #{e.message}")
    render json: { error: 'Internal server error' }, status: :internal_server_error
  end

  rescue_from ActiveRecord::RecordNotFound do
    render json: { error: 'Resource not found' }, status: :not_found
  end

  rescue_from ActiveRecord::RecordInvalid do |e|
    render json: { error: e.message, details: e.record.errors.full_messages }, status: :unprocessable_entity
  end

  rescue_from ActionController::ParameterMissing do |e|
    render json: { error: "Missing parameter: #{e.param}" }, status: :bad_request
  end

  private

  def current_user_id
    request.env['jwt.user_id']
  end

  def current_user_email
    request.env['jwt.user_email']
  end

  def current_user_role
    request.env['jwt.user_role']
  end

  def current_user_roles
    Array(request.env['jwt.user_roles']).map { |role| role.to_s.downcase }
  end

  def admin?
    current_user_roles.intersect?(ADMIN_ROLES)
  end

  def super_admin?
    current_user_roles.intersect?(SUPER_ADMIN_ROLES)
  end

  def require_admin!
    return if admin?

    Rails.logger.warn("Forbidden: user #{current_user_id.inspect} with roles #{current_user_roles.inspect} " \
                      "attempted #{request.method} #{request.path}")
    render json: { error: 'Forbidden: administrator role required' }, status: :forbidden
  end

  def require_super_admin!
    return if super_admin?

    render json: { error: 'Forbidden: super_admin role required' }, status: :forbidden
  end

  def set_request_metadata
    @request_metadata = {
      ip_address: request.remote_ip,
      user_agent: request.user_agent
    }
  end

  def paginate(scope)
    page = [(params[:page] || 1).to_i, 1].max
    per_page = [(params[:per_page] || 20).to_i, 100].min.clamp(1, 100)
    total = scope.count

    records = scope.offset((page - 1) * per_page).limit(per_page)

    response.headers['X-Total-Count'] = total.to_s
    response.headers['X-Page'] = page.to_s
    response.headers['X-Per-Page'] = per_page.to_s

    { records: records, total: total, page: page, per_page: per_page }
  end
end
