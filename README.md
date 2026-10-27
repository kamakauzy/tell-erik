# tell-erik

Remote Telerik UI version enumerator for authorized assessments.

Reads the build from the HTML version comment, the AJAX CDN path (`/ajax/<build>/` or the gzip folder `/ajaxz/<build>/`), an assembly or resource-query string, or a Kendo CDN path or script banner. Confirms handlers with GET fingerprints.

Python 3.9+. Standard library only.

```bash
python3 tell-erik --url https://app.example/orders/default.aspx
python3 tell-erik --url https://app.example/orders/default.aspx --cookie 'ASP.NET_SessionId=...; .ASPXAUTH=...'
python3 tell-erik --self-test
```

## Auth

- `--cookie` value, without the `Cookie:` prefix
- `--bearer` token
- `--basic user:password`
- `--header 'Name: Value'`, repeatable
- `--form-url` with `--form-user`, `--form-password`, `--form-user-field`, `--form-pass-field`

Other flags: `--list`, `--proxy`, `--timeout`, `--insecure`, `--scanner-ua`, `--no-walk`, `--json`.

Exit 0 when a version or a handler is present, 2 on a clean miss, 1 on error.

## Encryption

`Telerik.ScriptManager.EnableHandlerEncryption` drops the HTML comment and encrypts `WebResource.axd`. The build is then in the CDN path, or on a page that still prints the comment. A skin served from the app keeps the version off the HTML. Handlers can still answer.

Published-range output compares `year.quarter.build` and ignores the framework suffix (`.40`, `.45`, `.462`).
