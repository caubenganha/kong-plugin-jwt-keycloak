local url = require "socket.url"
local http = require "socket.http"
local https = require "ssl.https"
local cjson_safe = require "cjson.safe"
local convert = require "kong.plugins.jwt-keycloak.key_conversion"

local function get_request(url, scheme, port, token)
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
    if token
    then
        res, status = req({
            url = url,
            sink = ltn12.sink.table(chunks),
            headers = { 
                authorization = "Bearer " .. token,
                host = "10.90.10.206:8080"
            }
        })
    else
        res, status = req({
            url = url,
            port = port,
            sink = ltn12.sink.table(chunks)
        })
    end

    if status ~= 200 then
        return nil, 'Failed calling url ' .. url .. ' response status ' .. status
    end

    res, err = cjson_safe.decode(table.concat(chunks))
    if not res then
        return nil, 'Failed to parse json response'
    end
    
    return res, nil
end

local function get_wellknown_endpoint(well_known_template, issuer)
    return string.format(well_known_template, issuer)
end

local function get_user_attr(user_attributes_template, token)
    local req = url.parse(user_attributes_template)
    local res, err = get_request(user_attributes_template, req.scheme, req.port, token)
    if err then
        kong.log.err('err: ' ..err)
        return nil, err
    end
    kong.log.debug(res)
    local keys = {}
    for i, key in ipairs(res[0]['api-access']['apis']) do
        kong.log.debug('api-access declares in keycloak: ' .. key)
        keys[i] = key
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
    get_user_attr = get_user_attr,
    get_issuer_keys = get_issuer_keys,
    get_wellknown_endpoint = get_wellknown_endpoint,
}