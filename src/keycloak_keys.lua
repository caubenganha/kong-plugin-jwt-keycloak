local url = require "socket.url"
local http = require "socket.http"
local https = require "ssl.https"
local cjson_safe = require "cjson.safe"
local json = require "kong.plugins.jwt-keycloak.json"
local convert = require "kong.plugins.jwt-keycloak.key_conversion"

local function get_request(url, scheme, port)
    local req
    if scheme == "https" then
        req = https.request
    else
        req = http.request
    end

    local res
    local status
    local err

    local chunks = {}
    res, status = req({
        url = url,
        port = port,
        sink = ltn12.sink.table(chunks)
    })

    if status ~= 200 then
        return nil, 'Failed calling url ' .. url .. ' response status ' .. status
    end
    res, err = cjson_safe.decode(table.concat(chunks))
    if not res then
        return nil, 'Failed to parse json response'
    end
    return res, nil
end

local function get_request_token(url, schema_request, token)
    local req
    if schema_request.scheme == "https" then
        req = https.request
    else
        req = http.request
    end

    local res
    local status
    local err
    kong.log.debug("host keycloak:"..schema_request.host..":"..schema_request.port)
    local chunks = {}
    if token then
        res, status = req({
            url = url,
            sink = ltn12.sink.table(chunks),
            headers = { 
                authorization = "Bearer " .. token,
                host = schema_request.host..":"..schema_request.port
            }
        })
    end

    if status ~= 200 then
        return nil, 'Failed calling url ' .. url .. ' response status ' .. status
    end
    print("API access in string: ", tostring(table.concat(chunks)))
    local res_data, err = json.decode(table.concat(chunks))
    if not res_data then
        kong.log.err(err)
        return nil, err
    end
    -- print("firstName access: ", tostring(json_data["firstName"]))
    -- print("lastName access: ", tostring(json_data["lastName"]))
    -- print("email access: ", tostring(json_data["email"]))
    return res_data, nil
end

local function get_wellknown_endpoint(well_known_template, issuer)
    return string.format(well_known_template, issuer)
end

local function get_role_attr(role_attributes_template, token)
    local req = url.parse(role_attributes_template)
    local res, err = get_request_token(role_attributes_template, req, token)
    if err then
        kong.log.err('err: ' ..err)
        return nil, err
    end
    local keys = {}
    for i, value in ipairs(res) do
        keys[i] = value
    end
    return keys, nil
end

local function get_issuer_keys(well_known_endpoint)
    -- Get port of the request: This is done because keycloak 3.X.X does not play well with lua socket.http
    local req = url.parse(well_known_endpoint)

    local res, err = get_request(well_known_endpoint, req.scheme, req.port)
    if err then
        return nil, err
    end

    local res, err = get_request(res['jwks_uri'], req.scheme,  req.port)
    if err then
        return nil, err
    end

    local keys = {}
    for i, key in ipairs(res['keys']) do
        keys[i] = string.gsub(
            convert.convert_kc_key(key), 
            "[\r\n]+", ""
        )
    end
    return keys, nil
end

return {
    get_request = get_request,
    get_role_attr = get_role_attr,
    get_issuer_keys = get_issuer_keys,
    get_wellknown_endpoint = get_wellknown_endpoint,
}