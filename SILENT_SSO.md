# Silent SSO (OIDC prompt=none) Support

## What is Silent SSO?
Silent SSO allows a client (SPA, web app) to check for an existing SSO session in the background, without user interaction. This is done by sending the OpenID Connect `prompt=none` parameter to the `/o/authorize/` endpoint.

- If the user is already authenticated, tokens are issued without showing a login screen.
- If not, the server redirects with an error (e.g., `error=login_required`).

## How is it supported in this project?
- The `/o/authorize/` endpoint is provided by django-oauth-toolkit and already supports `prompt=none`.
- If the user is not logged in and `prompt=none` is sent, the server responds with an OIDC-compliant error.
- No backend code changes are required for basic silent SSO support.

## How to use from a frontend (example)
- Use a library like `angular-oauth2-oidc` or similar.
- Configure a silent refresh iframe or background request with `prompt=none`:

```js
const params = new URLSearchParams({
  client_id: 'your-client-id',
  redirect_uri: window.location.origin + '/callback',
  response_type: 'code',
  scope: 'openid profile email',
  prompt: 'none',
});
window.location.href = `${SSO_URL}/o/authorize/?${params}`;
```

- If the user is logged in, you get a code/token. If not, handle the error in your callback handler.

## References
- [OIDC Core Spec: prompt parameter](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest)
- [django-oauth-toolkit docs](https://django-oauth-toolkit.readthedocs.io/en/latest/)

---

**No backend changes are required for prompt=none support.**
If you want custom behavior, subclass `AuthorizationView` and update your URLs.
