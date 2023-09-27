rule detect_synapse_token : tokens
{
    meta:
        Author = "MTRNord"
        Description = "This detects synapse access tokens. The synapse tokens all start with 'syt_'"
        Action = "RedactAndNotify"
        NotifcationText = "Matrix access token detected. Please remove it before sending your message again."
    strings:
        $synapse_pattern = /syt_.{1,340}_.{20}_.{6}/

    condition:
        $synapse_pattern
}

rule detect_github_token : tokens
{
    meta:
        Author = "MTRNord"
        Description = "This detects github access tokens. See https://github.blog/2021-04-05-behind-githubs-new-authentication-token-formats/"
        Action = "RedactAndNotify"
        NotifcationText = "Github access token detected. Please remove it before sending your message again. If this is a falsepositive make sure to include `tokenbypass1CwRlV5VtQdDPh`"
    strings:
        $personal_access_token = "ghp_"
        $oauth_access_token = "gho_"
        $user_to_server_token = "ghu_"
        $server_to_server_token = "ghs_"
        $refresh_token = "ghr_"
        $bypass = "tokenbypass1CwRlV5VtQdDPh"

    condition:
        ($personal_access_token or $oauth_access_token or $user_to_server_token or $server_to_server_token or $refresh_token) and not $bypass
}