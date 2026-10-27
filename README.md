# tell-erik

A SecurIT360 tool. Version 0.3.0.

Remote Telerik UI version enumerator.

Reads the build from the assembly or resource-query string, the HTML version comment, the AJAX CDN path (`/ajax/<build>/` or the gzip folder `/ajaxz/<build>/`), or a Kendo CDN path or script banner. A linked CDN stylesheet or script is fetched and checked. Handlers are confirmed with GET fingerprints.

The assembly string outranks the comment, and the comment outranks the CDN path. An AJAX stylesheet confirms when the body is CSS with a `.Rad` rule. The CSS does not repeat the version. A Kendo script confirms from the `Kendo UI v…` banner in the file, and that banner outranks the path when the two builds differ. Published ranges use the server-stated build when one is present, and a confirmed skin when the page has nothing else. A path whose file does not confirm does not drive a range.

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

## Extension

v0.3.0 reads the same file. A dialog page and a plaintext resource query are checked when the ASP.NET AJAX build is missing from the main page. Handler-specific ranges stay outside when that handler is a 404. The popup shows CISA KEV and the EPSS snapshot date in the definition file.

Chrome or Edge. On the extensions page, turn on developer mode, choose Load unpacked, and select the `extension/` folder. Open the app, then click the icon. The read uses that tab's session. Reload the unpacked extension for v0.2.0. After that, a higher `version` in `definitions.json` updates the ranges without another reload. The popup line shows the number and whether it came from the repo, a saved copy, or the copy packed in the extension.

The grant on the tab is the click (`activeTab`, `scripting`). The popup also fetches the Telerik AJAX CDN and the two Kendo CDNs, with credentials omitted, to check the file the page linked.

## Encryption

`Telerik.ScriptManager.EnableHandlerEncryption` drops the HTML comment and encrypts `WebResource.axd`. The build is then in the CDN path, or on a page that still prints the comment. A skin served from the app keeps the version off the HTML. Handlers can still answer.

Published-range output compares `year.quarter.build` and ignores the framework suffix (`.40`, `.45`, `.462`).
