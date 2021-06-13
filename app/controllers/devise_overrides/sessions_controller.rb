class DeviseOverrides::SessionsController < ::DeviseTokenAuth::SessionsController
  # Prevent session parameter from being passed
  # Unpermitted parameter: session
  wrap_parameters format: []
  before_action :process_sso_auth_token, only: [:create]

  def create
    # Authenticate user via the temporary sso auth token
    #logger.info 'Processing the request... ########################################1'
    if params[:sso_auth_token].present? && @resource.present?
      authenticate_resource_with_sso_token
      yield @resource if block_given?
      render_create_success
    else
      if (!params[:tokenAuth0].blank?)
        userAuth = loginUserWithAUth0
        if (!userAuth)
          return render json: { "message": 'Invalid credantial' }, status: 401
        end
        logger.info 'Processing the request... ########################################3' +
                      userAuth.email
      end
      super
    end
  end

  def render_create_success
    render partial: 'devise/auth.json', locals: { resource: @resource }
  end

  private

  def authenticate_resource_with_sso_token
    @token = @resource.create_token
    @resource.save

    sign_in(:user, @resource, store: false, bypass: false)

    # invalidate the token after the user is signed in
    @resource.invalidate_sso_auth_token(params[:sso_auth_token])
  end

  def process_sso_auth_token
    return if params[:email].blank?

    user = User.find_by(email:  params[:email])
    @resource = user if user&.valid_sso_auth_token?(params[:sso_auth_token])
  end

  def loginUserWithAUth0
    url = ENV['AUTH_BASE_URL'] + '/userinfo'
    token = params[:tokenAuth0]
    result =
      Faraday.get(ENV['AUTH_BASE_URL'] + '/userinfo') do |req|
        req.headers['Authorization'] = 'Bearer ' + token
      end

    if (result && valid_json?(result.body) && JSON.parse(result.body)['email'])
      user = User.find_by(email: JSON.parse(result.body)['email'])
      @resource = user
    else
      return nil
    end
  end

  def valid_json?(json)
    JSON.parse(json)
    return true
  rescue JSON::ParserError => e
    return false
  end
end
