"""OAuth helpers that preserve local behavior while supporting Docker callbacks."""

from __future__ import annotations

import asyncio
import os
import socket
import sys
import threading
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Callable


def is_running_in_docker() -> bool:
    """Best-effort container detection for CLI-specific behavior."""
    if os.environ.get("NANOBOT_RUNNING_IN_DOCKER", "").strip().lower() in {"1", "true", "yes"}:
        return True

    if Path("/.dockerenv").exists():
        return True

    cgroup_path = Path("/proc/1/cgroup")
    try:
        content = cgroup_path.read_text(encoding="utf-8")
    except OSError:
        return False

    markers = ("docker", "containerd", "kubepods", "podman")
    return any(marker in content for marker in markers)


class _OAuthHandler(BaseHTTPRequestHandler):
    """Minimal OAuth callback handler with configurable path/state validation."""

    server_version = "NanoBotOAuth/1.0"
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802
        try:
            url = urllib.parse.urlparse(self.path)
            if url.path != self.server.callback_path:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"Not found")
                return

            qs = urllib.parse.parse_qs(url.query)
            code = qs.get("code", [None])[0]
            state = qs.get("state", [None])[0]

            if state != self.server.expected_state:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"State mismatch")
                return

            if not code:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Missing code")
                return

            try:
                self.server.on_code(code)
            except Exception:
                pass

            body = (
                "<!doctype html><html><body><h1>Login complete</h1>"
                "<p>You can close this tab and return to NanoBot.</p></body></html>"
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            try:
                self.wfile.flush()
            except Exception:
                pass
            self.close_connection = True
        except Exception:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b"Internal error")

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
        return


class _OAuthCallbackServer(HTTPServer):
    """HTTP callback server carrying expected state and callback metadata."""

    def __init__(
        self,
        server_address: tuple[str, int],
        expected_state: str,
        callback_path: str,
        on_code: Callable[[str], None],
    ) -> None:
        super().__init__(server_address, _OAuthHandler)
        self.expected_state = expected_state
        self.callback_path = callback_path
        self.on_code = on_code


def _read_stdin_line_sync_fallback() -> str:
    return sys.stdin.readline()


async def _read_stdin_line() -> str:
    loop = asyncio.get_running_loop()
    if hasattr(loop, "add_reader") and sys.stdin:
        future: asyncio.Future[str] = loop.create_future()

        def _on_readable() -> None:
            line = sys.stdin.readline()
            if not future.done():
                future.set_result(line)

        try:
            loop.add_reader(sys.stdin, _on_readable)
        except Exception:
            return await loop.run_in_executor(None, _read_stdin_line_sync_fallback)

        try:
            return await future
        finally:
            try:
                loop.remove_reader(sys.stdin)
            except Exception:
                pass

    return await loop.run_in_executor(None, _read_stdin_line_sync_fallback)


async def _await_manual_input(print_fn: Callable[[str], None]) -> str:
    print_fn("[cyan]Paste the authorization code (or full redirect URL), or wait for the browser callback:[/cyan]")
    return await _read_stdin_line()


def _start_callback_server(
    *,
    bind_host: str,
    port: int,
    callback_path: str,
    state: str,
    on_code: Callable[[str], None],
) -> tuple[_OAuthCallbackServer | None, str | None]:
    try:
        addrinfos = socket.getaddrinfo(bind_host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        return None, f"Failed to resolve callback bind host {bind_host}: {exc}"

    last_error: OSError | None = None
    for family, _socktype, _proto, _canonname, sockaddr in addrinfos:
        try:
            class _AddrOAuthServer(_OAuthCallbackServer):
                address_family = family

            server = _AddrOAuthServer(sockaddr, state, callback_path, on_code)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            return server, None
        except OSError as exc:
            last_error = exc
            continue

    if last_error:
        return None, f"Local callback server failed to start: {last_error}"
    return None, "Local callback server failed to start: unknown error"


def login_oauth_interactive_for_container(
    *,
    print_fn: Callable[[str], None],
    prompt_fn: Callable[[str], str],
    provider: Any,
    originator: str | None = None,
    storage: Any = None,
    bind_host: str | None = None,
) -> Any:
    """Docker-aware OAuth login flow.

    The browser still redirects to the provider's registered callback URI. We
    only change the listener bind address so a published container port can
    receive that callback from the host.
    """
    from oauth_cli_kit.flow import FileTokenStorage, _exchange_code_for_token_async
    from oauth_cli_kit.pkce import _create_state, _generate_pkce, _parse_authorization_input

    redirect = urllib.parse.urlparse(provider.redirect_uri)
    callback_path = redirect.path or "/auth/callback"
    callback_port = redirect.port or (443 if redirect.scheme == "https" else 80)
    bind_host = bind_host or os.environ.get("NANOBOT_OAUTH_CALLBACK_BIND_HOST", "0.0.0.0")

    async def _login_async() -> Any:
        verifier, challenge = _generate_pkce()
        state = _create_state()
        params = {
            "response_type": "code",
            "client_id": provider.client_id,
            "redirect_uri": provider.redirect_uri,
            "scope": provider.scope,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": state,
            "id_token_add_organizations": "true",
            "codex_cli_simplified_flow": "true",
            "originator": originator or provider.default_originator,
        }
        url = f"{provider.authorize_url}?{urllib.parse.urlencode(params)}"

        loop = asyncio.get_running_loop()
        code_future: asyncio.Future[str] = loop.create_future()

        def _notify(code_value: str) -> None:
            if code_future.done():
                return
            loop.call_soon_threadsafe(code_future.set_result, code_value)

        server, server_error = _start_callback_server(
            bind_host=bind_host,
            port=callback_port,
            callback_path=callback_path,
            state=state,
            on_code=_notify,
        )

        print_fn("[cyan]Docker runtime detected. NanoBot will listen for the OAuth callback inside the container.[/cyan]")
        print_fn(
            f"[dim]Callback listener: {bind_host}:{callback_port}{callback_path} "
            f"(redirect URI remains {provider.redirect_uri})[/dim]"
        )
        print_fn(
            "[dim]If the container port is not published to the host, copy the final redirect URL or code back here.[/dim]"
        )
        print_fn("[cyan]A browser window will open for login. If it doesn't, open this URL manually:[/cyan]")
        print_fn(url)
        try:
            webbrowser.open(url)
        except Exception:
            pass

        if not server and server_error:
            print_fn(
                "[yellow]"
                f"Local callback server could not start ({server_error}). "
                "You will need to paste the callback URL or authorization code."
                "[/yellow]"
            )

        code: str | None = None
        try:
            if server:
                print_fn("[dim]Waiting for browser callback...[/dim]")
                callback_task = asyncio.create_task(asyncio.wait_for(code_future, timeout=120))
                manual_task = asyncio.create_task(_await_manual_input(print_fn))
                done, pending = await asyncio.wait(
                    [callback_task, manual_task],
                    return_when=asyncio.FIRST_COMPLETED,
                )
                for task in pending:
                    task.cancel()

                for task in done:
                    try:
                        result = task.result()
                    except asyncio.TimeoutError:
                        result = None
                    if not result:
                        continue
                    if task is manual_task:
                        parsed_code, parsed_state = _parse_authorization_input(result)
                        if parsed_state and parsed_state != state:
                            raise RuntimeError("State validation failed.")
                        code = parsed_code
                    else:
                        code = result
                    if code:
                        break

            if not code:
                raw = await loop.run_in_executor(
                    None,
                    prompt_fn,
                    "Please paste the callback URL or authorization code:",
                )
                parsed_code, parsed_state = _parse_authorization_input(raw)
                if parsed_state and parsed_state != state:
                    raise RuntimeError("State validation failed.")
                code = parsed_code

            if not code:
                raise RuntimeError("Authorization code not found.")

            print_fn("[dim]Exchanging authorization code for tokens...[/dim]")
            token = await _exchange_code_for_token_async(code, verifier, provider)()
            (storage or FileTokenStorage(token_filename=provider.token_filename)).save(token)
            return token
        finally:
            if server:
                server.shutdown()
                server.server_close()

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(_login_async())

    result: list[Any] = []
    error: list[Exception] = []

    def _runner() -> None:
        try:
            result.append(asyncio.run(_login_async()))
        except Exception as exc:
            error.append(exc)

    thread = threading.Thread(target=_runner)
    thread.start()
    thread.join()
    if error:
        raise error[0]
    return result[0]
