using System.Text.Json.Serialization;

namespace OidcBrute;

public class Auth0JwtTokensResponse
{
    [JsonPropertyName("access_token")]
    public string AccessToken { get; set; } = string.Empty;

    [JsonPropertyName("id_token")]
    public string IdToken { get; set; } = string.Empty;

    [JsonPropertyName("refresh_token")]
    public string RefreshToken { get; set; } = string.Empty;

    [JsonPropertyName("expires_in")]
    public long ExpiresIn { get; set; }

    public string Scope { get; set; } = string.Empty;

    [JsonPropertyName("token_type")]
    public string TokenType { get; set; } = string.Empty;
}

public class Auth0JwtWellKnownResponse<TKey>
{
    public TKey[] Keys { get; set; } = Array.Empty<TKey>();
}

public class EcSigningKey
{
    public string X { get; set; } = string.Empty;

    public string Y { get; set; } = string.Empty;
}

public class RsaSigningKey
{
    [JsonPropertyName("alg")]
    public string Algoritm { get; set; } = string.Empty;

    [JsonPropertyName("kty")]
    public string Kitty { get; set; } = string.Empty;

    public string Use { get; set; } = string.Empty;

    [JsonPropertyName("n")]
    public string Modulus { get; set; } = string.Empty;

    [JsonPropertyName("e")]
    public string Exponent { get; set; } = string.Empty;
}