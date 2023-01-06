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
    local role_attributes = {}
    local roles_in_token = token_claims.realm_access.roles
    kong.log.debug('get  user_role')
    for _, curr_claim_role in pairs(roles_in_token) do
        -- kong.log.debug('curr_allowed_api 1 ' .. curr_role["name"])
        for _, value in pairs(roles_cofiguration) do
            if value.name == curr_claim_role then
                table.insert(role_attributes, value)
            end
        end
    end

    -- Check api_access in user_role which match route
    kong.log.debug("Match api_access in roles")
    local validate_api_access, api_error = match_roles_access(role_attributes, route)
    if validate_api_access then
        return true
    else
        kong.log.debug(api_error)
        return nil, api_error
    end
end

local function validate_group_access(group_attributes_template, role_attributes_template, token_claims, token)
    local route = kong.router.get_route().name
    kong.log.debug('validate_group_access route name' .. route)

    local groups_cofiguration, err = get_data(group_attributes_template, token)
    if err then
        return nil, err
    end

    -- Get user groups (detail) from list group
    local user_groups = {}
    local groups_in_token = token_claims.group_access
    kong.log.debug('get groups_cofiguration ')
    for _, group in pairs(groups_in_token) do
        -- kong.log.debug('curr_allowed_api 1 ' .. curr_role["name"])
        for _, value in ipairs(groups_cofiguration) do
            if value.path == group then
                table.insert(user_groups, value)
            end
        end
    end

    -- Check api_access in user_role which match route
    kong.log.debug("Match api_access in groups")
    local keycloak_roles_configuration, err = get_data(role_attributes_template, token)
    if err then
        return nil, err
    end

    local validate_api_access, api_error = match_groups_access(user_groups, keycloak_roles_configuration, route)
    if validate_api_access then
        return true
    else
        kong.log.debug(api_error)
        return nil, api_error
    end

end

function match_groups_access(user_groups, keycloak_roles_configuration, route)
    kong.log.debug("match_groups_access")
    if user_groups == nil or #user_groups == 0 then
        return false, "Groups or roles of user is not configed in keycloak "
    end
    --Get realm roles name from user_groups (UUID type)
    local roles_name = {}
    for _, realm_role in pairs(user_groups) do
        if realm_role ~= nil and #realm_role.realmRoles then
            for index, value in ipairs(realm_role.realmRoles) do
                kong.log.debug("realmRoles "..value)
                table.insert(roles_name, value)
            end
        end
    end
    --Match roles_name with keycloak_roles_configuration
    kong.log.debug("Match role details")
    local role_details = {}
    for _, role in pairs(roles_name) do
        for _, role_config in pairs(keycloak_roles_configuration) do
            if role_config.name == role then
                table.insert(role_details, role_config)
            end
        end
    end


    kong.log.debug("Match api_access")
    for _, role in pairs(role_details) do
        kong.log.debug('api_access.attributes.api_access size: ' .. #role.attributes)
        if role.attributes ~= nil and role.attributes.api_access ~= nil and #role.attributes.api_access > 0 then
            for _, api in pairs(json.decode(table.concat(role.attributes.api_access))) do
                kong.log.debug('validate_group_access API: ' .. api)
                if api == route then
                    return true
                end
            end
        end
    end
    return false, "You have no role permission or group permission on the api".. route
end


function match_roles_access(user_group, route)

    if user_group == nil or #user_group == 0 then
        return false, "Groups or roles of user is not configed in keycloak "
    end

    kong.log.debug("Match api_access")
    for _, api_access in pairs(user_group) do
        local check = (api_access.attributes ~= nil)
        kong.log.debug('api_access.attributes != null: ' .. tostring(check))
        kong.log.debug('api_access.attributes.api_access size: ' .. #api_access.attributes)
        if api_access.attributes ~= nil and api_access.attributes.api_access ~= nil and #api_access.attributes.api_access > 0 then
            for _, api in pairs(json.decode(table.concat(api_access.attributes.api_access))) do
                kong.log.debug('validate_group_access API: ' .. api)
                if api == route then
                    return true
                end
            end
        end
    end
    return false, "You have no role permission or group permission on the api".. route
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
