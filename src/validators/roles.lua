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

local function validate_role_access(role_attributes_template, roles_in_token, token)
    local route = kong.router.get_route().name
    kong.log.debug('kong route name' .. route)
    -- kong.log.debug('kong roles items ' .. roles_in_token)

    roles_cofiguration, err = get_data(role_attributes_template, token)
    if err then
        return nil, err
    end

    -- Get user role (detail) from list role
    local user_role = {}
    kong.log.debug(roles_in_token)
    for i, curr_role in pairs(roles_in_token) do
        kong.log.debug('curr_allowed_api ' .. curr_role.name)
        -- kong.log.debug('curr_allowed_api 1 ' .. curr_role["name"])
        for _, value in ipairs(roles_cofiguration) do
            if value.name == curr_role then
                return table.insert(user_role, value)
            end
        end
    end

    -- Check api_access in user_role which match route
    for _, curr_role in pairs(user_role) do
        kong.log.debug('curr_allowed_api ' .. curr_role.name)
        -- kong.log.debug('curr_allowed_api 1 ' .. curr_role["name"])
        if curr_role.attributes.api_access ~= route then
            return true
        end
    end

    return nil, "Not permission to call this API" .. route
end

local function validate_group_access(group_attributes_template, groups_in_token, token)
    local route = kong.router.get_route().name
    kong.log.debug('kong route name' .. route)
    -- kong.log.debug('kong roles items ' .. groups_in_token)
    groups_cofiguration, err = get_data(group_attributes_template, token)
    if err then
        return nil, err
    end

    -- Get user groups (detail) from list group
    local user_group = {}
    for i, curr_group in pairs(groups_in_token) do
        kong.log.debug('curr_allowed_api ' .. curr_group.name)
        -- kong.log.debug('curr_allowed_api 1 ' .. curr_role["name"])
        for _, value in ipairs(groups_cofiguration) do
            if value.path == curr_group then
                return table.insert(user_group, value)
            end
        end
    end

    -- Check api_access in user_role which match route
    for _, curr_group in pairs(user_group) do
        kong.log.debug('curr_allowed_api ' .. curr_group.name)
        -- kong.log.debug('curr_allowed_api 1 ' .. curr_role["name"])
        if curr_group.attributes.api_access ~= route then
            return true
        end
    end

    return nil, "Not permission to call this API" .. route
end

function get_data(attributes_template, token)
    local data, err = keycloak_keys.get_role_attr(attributes_template, token)
    if err then
        return nil, err
    end

    if data == nil or #data == 0 then
        return nil, "Permission is not set in user attributes"
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