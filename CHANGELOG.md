## 2.0.1

- Switch to stable `pointycastle` version

## 2.0.0-nullsafety.1

- Migrate to null safety
- **Breaking change:** `NTLMClient` now extends `BaseClient` making it much easier to compose. As a
  result, `Uri` objects are now required for URLs when making HTTP requests
- `NTLMClient.multipart` is now deprecated, use `NTLMClient.send` instead
- The `Type2Message` class is now immutable

## 1.3.0

- Add `headerPrefix` parameter to support servers only using the `Negotiate` authentication scheme

## 1.2.0

- Add support for authenticating when the server supports other authentication methods in addition
  to NTLM

## 1.1.0

- Add support for sending `MultipartRequest`s
- Add support for Flutter Web

## 1.0.0

- Initial version
