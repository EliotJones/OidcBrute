# OIDC Brute #

This is me trying to (minimally) understand the core of the OIDC Authorization Code Flow with PKCE while writing minimal code and using as few
dependencies as possible.

I find that every SAAS/tutorial offers a million different parts of the OIDC spec with a bunch of options and configurability and I just
wanted to implement the most basic flow.

I'm using Auth0 as the Identity Provider (IdP) to avoid the complications with setting up the IdP, e.g. IdentityServer, too.

## Steps ##

The actual steps are fairly simple:

1. Generate the code verifier and code challenge, basically random base64 strings where the challenge is derived from the verifier.
2. Redirect the user to the IdP with a URL containing your client id, the challenge and a bunch of other stuff.
3. IdP redirects you to the redirect URL defined in (2), assuming it is configured on the IdP passing a code in the querystring.
4. Take the code plus the code verifier and pass them to a different endpoint on the IdP to get the access token and id token (and refresh token if choosing the right scope in (2)).
5. Verify the received JWT access token using the certificate information exposed by the IdP conventional endpoint.

None of this implementation is secure, it just shows the plumbing for the steps with as few moving parts and as little code as possible.

## Notes ##

A few things wasted a bunch of time:

- Not passing the "audience" value in step (2) meant Auth0 returned an empty access token which could not be verified by jwt.io or step (5).
- Not setting Authentication Methods to "None" in the credentials tab of Auth0 for the application/client meaning step (4) returned 401.
- Not knowing where/how to get and validate the JWT with .NET in step (5).
- Disposing of the instance of `RSACryptoServiceProvider` when validating in step (5). Results in a `IDX10503: Signature validation failed. Token does not have a kid. Keys tried: 'System.Text.StringBuilder'` error every-other call.
- The new .NET minimal APIs seem to work weirdly with redirects, the whole thing is new to me, not sure I like it yet but for something like this it's nice to have less magic.

## References ##

- https://auth0.com/docs/get-started/authentication-and-authorization-flow/call-your-api-using-the-authorization-code-flow-with-pkce
- https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow
- https://github.com/tonyxu-io/pkce-generator/blob/master/index.html
- https://tonyxu-io.github.io/pkce-generator/
- https://developers.onelogin.com/openid-connect/api/authorization-code
- https://stackoverflow.com/a/41041219
- https://community.auth0.com/t/empty-payload-in-access-token/75952/6
