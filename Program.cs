using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace OidcBrute;

public class Program
{
    private static readonly JsonWebTokenHandler JsonWebTokenHandler = new JsonWebTokenHandler();
    private static readonly SemaphoreSlim LockWellKnown = new SemaphoreSlim(1, 1);
    private static RSAParameters? LoadedRsaParameters;
    private static readonly JsonSerializerOptions WebOptions = new JsonSerializerOptions(JsonSerializerDefaults.Web);
    private static readonly HttpClient Client = new HttpClient();

    public static void Main(string[] args)
    {
        var app = WebApplication.CreateBuilder(args).Build();

        app.MapGet("/login", Login);
        app.MapGet("/callback", Callback);

        app.MapGet("/home", (HttpContext _) => TemplatedHtmlResult(
            @"
<h1>OIDC Brute</h1>
<p>Writing brutally bad, brutally basic code to brute force OIDC understanding into my stupid head.</p>
<a href=""/login"">Login</a>"));
        app.MapGet("/loggedin", (HttpContext ctx) => TemplatedHtmlResult(
            $@"
<h1>Logged In!</h1>
<p>Logged in with id token: {ctx.Request.Cookies["idtok"]}.</p>"));

        app.MapGet("/", (HttpContext ctx) => ctx.Response.Redirect("/home"));

        app.Run();
    }

    private static IResult TemplatedHtmlResult(string html)
    {
        html = $@"
<!DOCTYPE html>
<html>
    <head><title>OIDC Brute</title></head>
    <body>
        {html}
    </body>
</html>";

        return Results.Content(html, "text/html");
    }

    /// <summary>
    /// In browser direct the user to the authorize page, they will log-in on Auth0
    /// and Auth0 will redirect them to our /callback?code={{somecode}} endpoint.
    /// </summary>
    private static void Login(HttpContext ctx)
    {
        var (verifier, challenge) = GenerateCodes();

        ctx.Response.Cookies.Append("ver", verifier, new CookieOptions
        {
            SameSite = SameSiteMode.Lax,
            // Secure = true, < we're working in localhost currently with no HTTPS configured
            HttpOnly = true
        });

        var state = GenerateState(ctx);

        ctx.Response.Redirect("https://dev-x280oizjlvec4psm.us.auth0.com/authorize?client_id=pdYYa1ECzOcolXJGoH9urgxyRDkPras6" +
                              "&response_type=code&redirect_uri=http%3A%2F%2Flocalhost%3A7000%2Fcallback" +
                              $"&code_challenge={challenge}&code_challenge_method=S256" +
                              "&scope=openid%20profile%20offline_access" +
                              "&audience=http%3A%2F%2Flocalhost%3A7000" +
                              $"&state={state}");

        // Failing to provide audience in this call returns an invalid/empty access_token
        // but it doesn't really seem to be documented anywhere.
    }

    /// <summary>
    /// Once we get the code response post-login then we need to swap the code for the id + access token.
    /// </summary>
    private static async Task<IResult> Callback(HttpContext ctx)
    {
        var code = ctx.Request.Query["code"];

        if (!ctx.Request.Cookies.TryGetValue("ver", out var codever))
        {
            return Results.BadRequest("No verification cookie on client.");
        }

        if (!ctx.Request.Cookies.TryGetValue("idp-state", out var state)
            || state != ctx.Request.Query["state"])
        {
            return Results.BadRequest("State mismatch!");
        }

        var querystring = string.Empty;
        if (ctx.Request.Cookies.TryGetValue(state, out var jsonPayload)
            && !string.IsNullOrWhiteSpace(jsonPayload))
        {
            var item = JsonSerializer.Deserialize<JsonPayloadForState>(jsonPayload, WebOptions);

            querystring = item?.Query ?? string.Empty;

            ctx.Response.Cookies.Delete(state);
        }

        ctx.Response.Cookies.Delete("ver");
        ctx.Response.Cookies.Delete("idp-state");

        var token = await SwapCodeForToken(code, codever!);

        var parsed = JsonSerializer.Deserialize<Auth0JwtTokensResponse>(token, WebOptions);

        var isValid = await ValidateJwt(parsed!);

        if (!isValid)
        {
            return Results.BadRequest("You smell of elderberries.");
        }

        ctx.Response.Cookies.Append("idtok", parsed!.IdToken, new CookieOptions
        {
            SameSite = SameSiteMode.Lax,
            HttpOnly = false
        });
        ctx.Response.Cookies.Append("acctok", parsed.AccessToken, new CookieOptions
        {
            SameSite = SameSiteMode.Lax,
            HttpOnly = false
        });
        ctx.Response.Cookies.Append("reftok", parsed.RefreshToken, new CookieOptions
        {
            SameSite = SameSiteMode.Lax,
            HttpOnly = false
        });

        ctx.Response.Redirect("/loggedin");

        return Results.Redirect("/loggedin");
    }

    /// <summary>
    /// Parameters for validating the access token JWT are available on the Auth0 well known endpoint for our tenant.
    /// Load them once then cache.
    /// </summary>
    private static async Task<RSAParameters> LoadRsaParameters()
    {
        if (LoadedRsaParameters.HasValue)
        {
            return LoadedRsaParameters.Value;
        }

        await LockWellKnown.WaitAsync();

        try
        {
            if (LoadedRsaParameters.HasValue)
            {
                return LoadedRsaParameters.Value;
            }

            // https://community.auth0.com/t/where-is-the-auth0-public-key-to-be-used-in-jwt-io-to-verify-the-signature-of-a-rs256-token/8455
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://dev-x280oizjlvec4psm.us.auth0.com/.well-known/jwks.json");

            var response = await Client.SendAsync(request);

            var wellKnown = await response.Content.ReadFromJsonAsync<Auth0JwtWellKnownResponse>(WebOptions);

            var parameters = new RSAParameters
            {
                Modulus = Base64UrlEncoder.DecodeBytes(wellKnown!.Keys[0].Modulus),
                Exponent = Base64UrlEncoder.DecodeBytes(wellKnown.Keys[0].Exponent)
            };

            LoadedRsaParameters = parameters;

            return parameters;
        }
        finally
        {
            LockWellKnown.Release();
        }
    }

    private static string GenerateState(HttpContext ctx)
    {
        var query = ctx.Request.QueryString.ToUriComponent();

        var stateRaw = RandomNumberGenerator.GetBytes(32);

        var stateUrlSafe = B64Url(Convert.ToBase64String(stateRaw));

        // If stored in a cookie, it should be signed to prevent forgery. Not done in this example.
        ctx.Response.Cookies.Append(
            stateUrlSafe,
            JsonSerializer.Serialize(new JsonPayloadForState
            {
                Query = query
            }),
            new CookieOptions
            {
                SameSite = SameSiteMode.Lax,
                // Secure = true, < we're working in localhost currently with no HTTPS configured
                HttpOnly = true
            });
        ctx.Response.Cookies.Append(
            "idp-state",
            stateUrlSafe,
            new CookieOptions
            {
                // Secure = true,
                SameSite = SameSiteMode.Lax,
                HttpOnly = true
            });

        return stateUrlSafe;
    }

    /// <summary>
    /// Generate the challenge and challenge verifier. The challenge is provided with the initial /authenticate call
    /// and then the verifier with the code to swap on the /oauth/token call.
    /// </summary>
    private static (string verifier, string challenge) GenerateCodes()
    {
        // https://tonyxu-io.github.io/pkce-generator/
        var prng = RandomNumberGenerator.GetBytes(32);

        var b64 = Convert.ToBase64String(prng);

        var verifier = B64Url(b64);

        using var sha256 = SHA256.Create();

        var challengeHash = sha256.ComputeHash(Encoding.UTF8.GetBytes(verifier));

        var challenge = B64Url(Convert.ToBase64String(challengeHash));

        return (verifier, challenge);
    }

    /// <summary>
    /// Make the HTTP request to swap the code for the access/id token.
    /// </summary>
    private static async Task<string> SwapCodeForToken(string code, string challengerVerifier)
    {
        using var requestmessage = new HttpRequestMessage(
            HttpMethod.Post,
            "https://dev-x280oizjlvec4psm.us.auth0.com/oauth/token");

        requestmessage.Content = new FormUrlEncodedContent(
            new Dictionary<string, string>
            {
                { "grant_type", "authorization_code" },
                { "client_id", "pdYYa1ECzOcolXJGoH9urgxyRDkPras6" },
                { "code_verifier", challengerVerifier },
                { "code", code },
                { "redirect_uri", "http://localhost:7000/callback" }
            });

        requestmessage.Content.Headers.ContentType = new MediaTypeHeaderValue("application/x-www-form-urlencoded");

        using var response = await Client.SendAsync(requestmessage);

        var res = await response.Content.ReadAsStringAsync();

        return res;
    }

    /// <summary>
    /// Validate the returned JWT including audience, issuer and signing key (RSA 256 for Auth0).
    /// </summary>
    private static async Task<bool> ValidateJwt(Auth0JwtTokensResponse response)
    {
        var parameters = await LoadRsaParameters();

        var rsa = new RSACryptoServiceProvider();
        rsa.ImportParameters(parameters);

        var validationParameters = new TokenValidationParameters
        {
            ValidAudience = "http://localhost:7000",
            ValidAlgorithms = new[] { "RS256" },
            ValidIssuers = new[] { "https://dev-x280oizjlvec4psm.us.auth0.com/" },
            RequireExpirationTime = true,
            RequireSignedTokens = true,
            ValidateAudience = true,
            ValidateIssuer = true,
            ValidateLifetime = true,
            IssuerSigningKey = new RsaSecurityKey(rsa)
        };

        var r = await JsonWebTokenHandler.ValidateTokenAsync(response.AccessToken, validationParameters);

        return r.IsValid;
    }

    /// <summary>
    /// Encode a string as Base64 in a URL compatible way.
    /// </summary>
    private static string B64Url(string s)
        => s.Replace("=", string.Empty)
            .Replace('+', '-')
            .Replace('/', '_');
}

public class JsonPayloadForState
{
    public string? Query { get; set; }
}