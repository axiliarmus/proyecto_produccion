import os
from core.app_factory import app, create_app, ensure_mongo_indexes, set_tunnel_url
from core.runtime import maybe_start_tunnel, print_startup_banner


if __name__ == "__main__":
    server_app = create_app()
    maybe_start_tunnel(
        enabled=os.getenv("ENABLE_TUNNEL") == "true",
        set_tunnel_url=lambda url: set_tunnel_url(server_app, url),
    )
    print_startup_banner()
    server_app.run(host="0.0.0.0", port=5000)

