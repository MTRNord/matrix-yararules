rule detect_synapse_token : tokens
{
    meta:
        sharing = "TLP:CLEAR"
        author = "MTRNord"
        reference = "https://github.com/matrix-org/synapse/blob/11c6cc1115f43bf7bf1f8b99163ec3cdfa5003d9/synapse/handlers/auth.py#L1446-L1447"
        description = "This detects synapse access tokens. The synapse tokens all start with 'syt_'"
        Action = "RedactAndNotify"
        NotifcationText = "Matrix access token detected. Please remove and revoke(!) it before sending your message again."
    strings:
        $synapse_pattern = /syt_.{1,340}_.{20}_.{6}/ ascii

    condition:
        $synapse_pattern
}

rule detect_github_token : tokens
{
    meta:
        sharing = "TLP:CLEAR"
        author = "MTRNord"
        reference = "https://github.blog/2021-04-05-behind-githubs-new-authentication-token-formats/"
        description = "This detects github access tokens. See https://github.blog/2021-04-05-behind-githubs-new-authentication-token-formats/"
        Action = "RedactAndNotify"
        NotifcationText = "Github access token detected. Please remove and revoke(!) it before sending your message again. If this is a falsepositive make sure to include `tokenbypass1CwRlV5VtQdDPh`"
    strings:
        $personal_access_token = "ghp_" ascii fullword
        $oauth_access_token = "gho_" ascii fullword
        $user_to_server_token = "ghu_" ascii fullword
        $server_to_server_token = "ghs_" ascii fullword
        $refresh_token = "ghr_" ascii fullword
        $bypass = "tokenbypass1CwRlV5VtQdDPh" ascii fullword

    condition:
        ($personal_access_token or $oauth_access_token or $user_to_server_token or $server_to_server_token or $refresh_token) and not $bypass
}