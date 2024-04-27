# Temporary Auth Proxy

`tmp-auth-proxy` is a middleware for Traefik designed to secure web applications by managing JWT-based access. It enables URL sharing with a JWT that authenticates, redirects, and initiates a session for continued access.

Example JWT claims:

```
{
    "sub": "share/xmhbqiKHIPrQhXaKu6CmB2cNFv_hF1fM8P3OhiOt",
    "aud": "photos.example.org",
    "exp": 1714234852,
    "iat": 1714235852,
    "sec": false,
    "ses": 3600
}
```

When the proxy recieves a request to `http://photos.example.org/_/${SIGNED_JWT}` it will verify the signature of the JWT and if correct will redirect to `https://photos.example.org/share/xmhbqiKHIPrQhXaKu6CmB2cNFv_hF1fM8P3OhiOt`. It will also establish a session with duration specified by the `ses` claim (or the same as the validity of the JWT). The `sec` claim specifies whether to redirect to `http` or `https`. If omited will default to `https`.
