local json = require "kong.plugins.jwt-keycloak.json"

local keycloak_keys = require("kong.plugins.jwt-keycloak.keycloak_keys")

local function validate_client_roles(allowed_client_roles, jwt_claims)
    if allowed_client_roles == nil or #allowed_client_roles == 0 then
        return true
    end

    if jwt_claims == nil or jwt_claims.resource_access == nil then
        return nil, "Missing required resource_access claim"
    end

    for _, allowed_client_role in pairs(allowed_client_roles) do
        for curr_allowed_client, curr_allowed_role in string.gmatch(allowed_client_role, "(%S+):(%S+)") do
            for claim_client, claim_client_roles in pairs(jwt_claims.resource_access) do
                if curr_allowed_client == claim_client then
                    for _, curr_claim_client_roles in pairs(claim_client_roles) do
                        for _, curr_claim_client_role in pairs(curr_claim_client_roles) do
                            if curr_claim_client_role == curr_allowed_role then
                                return true
                            end
                        end
                    end
                end
            end
        end
    end

    return nil, "Missing required role"
end

local function validate_roles(allowed_roles, jwt_claims)
    if allowed_roles == nil or #allowed_roles == 0 then
        return true
    end

    if jwt_claims.azp == nil then
        return nil, "Missing required azp claim"
    end

    local tmp_allowed = {}
    for i, allowed in pairs(allowed_roles) do
        tmp_allowed[i] = jwt_claims.azp .. ":" .. allowed
    end
    
    return validate_client_roles(tmp_allowed, jwt_claims)
end

local function validate_realm_roles(allowed_realm_roles, jwt_claims)
    if allowed_realm_roles == nil or #allowed_realm_roles == 0 then
        return true
    end

    if jwt_claims == nil or jwt_claims.realm_access == nil or jwt_claims.realm_access.roles == nil then
        return nil, "Missing required realm_access.roles claim"
    end

    for _, curr_claim_role in pairs(jwt_claims.realm_access.roles) do
        for _, curr_allowed_role in pairs(allowed_realm_roles) do
            if curr_claim_role == curr_allowed_role then
                return true
            end
        end
    end

    return nil, "Missing required realm role"
end

local function validate_role_access(role_attributes_template, token_claims, token)
    local route = kong.router.get_route().name
    kong.log.debug('validate_role_access route name' .. route)

    local roles_cofiguration, err = get_data(role_attributes_template, token)
    if err then
        return nil, err
    end

    -- Get user role (detail) from list role
    local keycloak_roles = {}
    local roles_in_token = token_claims.realm_access.roles
    kong.log.debug('get  user_role')
    for _, curr_claim_role in pairs(roles_in_token) do
        -- kong.log.debug('curr_allowed_api 1 ' .. curr_role["name"])
        for _, value in pairs(roles_cofiguration) do
            if value.name == curr_claim_role then
                table.insert(keycloak_roles, value)
            end
        end
    end

    -- Check api_access in user_role which match route
    if keycloak_roles == nil or #keycloak_roles == 0 then
        return nil, "Roles if not configed in keycloak " .. route
    end

    kong.log.debug('Match roles ')
    for _, api_access in pairs(keycloak_roles) do
        local check = (api_access.attributes ~= nil)
        kong.log.debug('validate_group_access null: '.. tostring(check))
        kong.log.debug('validate_group_access size: '..#api_access.attributes)
        if api_access.attributes ~= nil and #api_access.attributes > 0 then
            for _, api in pairs(json.decode(table.concat(api_access.attributes.api_access))) do
                kong.log.debug('validate_role_access API: '..api)
                if api == route then
                    return true
                end
            end
        end

    end
    kong.log.warn('validate_role_access Not permission to call this API')
    return nil, "Not permission to call this API: " .. route
end

local function validate_group_access(group_attributes_template, token_claims, token)
    local route = kong.router.get_route().name
    kong.log.debug('validate_group_access route name' .. route)

    local groups_cofiguration, err = get_data(group_attributes_template, token)
    if err then
        return nil, err
    end

    -- Get user groups (detail) from list group
    local user_group = {}
    local groups_in_token = token_claims.group_api_access
    kong.log.debug('get groups_cofiguration ')
    for _, group in pairs(groups_in_token) do
        -- kong.log.debug('curr_allowed_api 1 ' .. curr_role["name"])
        for _, value in ipairs(groups_cofiguration) do
            if value.path == group then
                table.insert(user_group, value)
            end
        end
    end

    if user_group == nil or #user_group == 0 then
        return nil, "Groups if not configed in keycloak " .. route
    end

    -- Check api_access in user_role which match route
    kong.log.debug('match groups_cofiguration ')
    for _, api_access in pairs(user_group) do
        kong.log.debug('validate_group_access null: '..api_access.attributes ~= nil)
        kong.log.debug('validate_group_access size: '..#api_access.attributes)
        if api_access.attributes ~= nil and #api_access.attributes > 0 then
            for _, api in pairs(json.decode(table.concat(api_access.attributes.api_access))) do
                kong.log.debug('validate_group_access API: '..api)
                if api == route then
                    return true
                end
            end
        end
    end
    kong.log.warn('validate_role_access Not permission to call this API')
    return nil, "Not permission to call this API: " .. route
end

function get_data(attributes_template, token)
    local data, err = keycloak_keys.get_role_attr(attributes_template, token)
    if err then
        return nil, err
    end

    if data == nil or #data == 0 then
        return nil, "Roles or groups is not create in keycloak"
    end
    return data

end

return {
    validate_client_roles = validate_client_roles,
    validate_realm_roles = validate_realm_roles,
    validate_roles = validate_roles,
    validate_role_access = validate_role_access,
    validate_group_access = validate_group_access
}