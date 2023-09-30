rule detect_synapse_token : tokens
{
    meta:
        sharing = "TLP:CLEAR"
        author = "MTRNord"
        reference = "https://github.com/matrix-org/synapse/blob/11c6cc1115f43bf7bf1f8b99163ec3cdfa5003d9/synapse/handlers/auth.py#L1446-L1447"
        hash = "825de8cbbd5cbdfd6efbff9038b3e2fbd1fc9fe6a6f73b50ee98dfead52bc3c6"
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
        hash = "baa9e39c5ae9c01bd248d92c6e63f6299d3ca37fc9f977bf92ecd927354fe84c"
        Action = "RedactAndNotify"
        NotifcationText = "Github access token detected. Please remove and revoke(!) it before sending your message again. If this is a falsepositive make sure to include `tokenbypass1CwRlV5VtQdDPh`"
    strings:
        $personal_access_token = /ghp_[A-Za-z0-9_]{1,255}/ ascii fullword
        $oauth_access_token = /gho_[A-Za-z0-9_]{1,255}/ ascii fullword
        $user_to_server_token = /ghu_[A-Za-z0-9_]{1,255}/ ascii fullword
        $server_to_server_token = /ghs_[A-Za-z0-9_]{1,255}/ ascii fullword
        $refresh_token = /ghr_[A-Za-z0-9_]{1,255}/ ascii fullword
        $bypass = "tokenbypass1CwRlV5VtQdDPh" ascii fullword

    condition:
        ($personal_access_token or $oauth_access_token or $user_to_server_token or $server_to_server_token or $refresh_token) and not $bypass
}