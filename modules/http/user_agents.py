USER_AGENTS = {
    "default": "ANDIKZZ-WORDPRESS/6.0",
    "browser": (
        "Mozilla/5.0 (Linux; Android 11) "
        "AppleWebKit/537.36 "
        "(KHTML, like Gecko) "
        "Chrome/120.0.0.0 Mobile Safari/537.36"
    ),
    "research": "ANDIKZZ-PASSIVE-RESEARCH/6.0"
}


def get_user_agent(profile="default"):
    return USER_AGENTS.get(
        profile,
        USER_AGENTS["default"]
    )
