module JwtHelper
  def jwt_token(user_id: SecureRandom.uuid, email: 'admin@otterworks.com', role: 'super_admin', roles: nil)
    payload = {
      sub: user_id,
      email: email,
      exp: 24.hours.from_now.to_i,
      iat: Time.current.to_i
    }
    # The auth-service issues a `roles` array; legacy tokens carry a single `role`.
    if roles
      payload[:roles] = roles
    else
      payload[:role] = role
    end
    secret = Rails.application.secrets.jwt_secret
    JWT.encode(payload, secret, 'HS256')
  end

  def auth_headers(user_id: SecureRandom.uuid, email: 'admin@otterworks.com', role: 'super_admin', roles: nil)
    token = jwt_token(user_id: user_id, email: email, role: role, roles: roles)
    { 'Authorization' => "Bearer #{token}" }
  end

  def set_jwt_env(request, user_id: SecureRandom.uuid, email: 'admin@otterworks.com', role: 'super_admin', roles: nil)
    request.env['jwt.user_id'] = user_id
    request.env['jwt.user_email'] = email
    request.env['jwt.user_role'] = role
    request.env['jwt.user_roles'] = (roles || [role]).map { |r| r.to_s.downcase }
  end
end

RSpec.configure do |config|
  config.include JwtHelper
end
