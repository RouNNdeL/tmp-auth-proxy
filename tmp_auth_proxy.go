package tmp_auth_proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Config struct {
	Secret        string
	PathPrefix    string
	SessionCookie string
	JWTLeeway     int
}

func CreateConfig() *Config {
	return &Config{
		Secret:        "changeme",
		PathPrefix:    "_",
		SessionCookie: "TMP_AUTH_SESSION",
		JWTLeeway:     300,
	}
}

func (c *Config) NormalizedPathPrefix() string {
	ret := c.PathPrefix
	if !strings.HasPrefix(c.PathPrefix, "/") {
		ret = "/" + ret
	}
	if !strings.HasSuffix(c.PathPrefix, "/") {
		ret = ret + "/"
	}

	return ret
}

type JWTAuth struct {
	next   http.Handler
	name   string
	config Config
}

type JWTAuthClaims struct {
	SessionDuration int `json:"ses"`
	jwt.RegisteredClaims
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	config_cpy := *config
	config_cpy.PathPrefix

	return &JWTAuth{
		next:   next,
		name:   name,
		config: *config,
	}, nil
}

type MyCustomClaims struct {
	Foo string `json:"foo"`
	jwt.RegisteredClaims
}

func (a *JWTAuth) ValidateSession(rw http.ResponseWriter, req *http.Request) bool {
	host := req.Host
	leeway := time.Duration(a.config.JWTLeeway) * time.Second
	sessionCookie, err := req.Cookie(a.config.SessionCookie)
	if err != nil {
		http.Error(rw, "Forbidden", http.StatusForbidden)
		return false
	}

	tokenString := sessionCookie.Value
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(a.config.Secret), nil
	}, jwt.WithExpirationRequired(), jwt.WithIssuedAt(), jwt.WithLeeway(leeway))

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		rw.Write([]byte("bad claims\n"))
		http.Error(rw, "Forbidden", http.StatusForbidden)
		return false
	}

	issuer, err := claims.GetIssuer()
	if err != nil {
		rw.Write([]byte(err.Error() + "\n"))
		http.Error(rw, "Forbidden", http.StatusForbidden)
		return false
	}

	if issuer != host {
		rw.Write([]byte("incorrect issuer\n"))
		http.Error(rw, "Forbidden", http.StatusForbidden)
		return false
	}

	return true
}

func (a *JWTAuth) HandleTokenUrl(rw http.ResponseWriter, req *http.Request, tokenString string) {
	host := req.Host
	leeway := time.Duration(a.config.JWTLeeway) * time.Second
	// ParseWithClaims does not seem to work properly wth yaegi
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(a.config.Secret), nil
	}, jwt.WithAudience(host), jwt.WithExpirationRequired(), jwt.WithIssuedAt(), jwt.WithLeeway(leeway))

	if err != nil || !token.Valid {
		rw.Write([]byte(err.Error() + "\n"))
		http.Error(rw, "Forbidden", http.StatusForbidden)
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		rw.Write([]byte("bad claims\n"))
		http.Error(rw, "Forbidden", http.StatusForbidden)
		return
	}

	targetUrlPath, err := claims.GetSubject()
	if err != nil {
		rw.Write([]byte(err.Error() + "\n"))
		http.Error(rw, "Forbidden", http.StatusForbidden)
		return
	}

	tokenExpP, err := claims.GetExpirationTime()
	if err != nil {
		rw.Write([]byte(err.Error() + "\n"))
		http.Error(rw, "Forbidden", http.StatusForbidden)
		return
	}
	tokenExp := *tokenExpP

	tokenIssuedAtP, err := claims.GetIssuedAt()
	if err != nil {
		rw.Write([]byte(err.Error() + "\n"))
		http.Error(rw, "Forbidden", http.StatusForbidden)
		return
	}
	tokenIssuedAt := *tokenIssuedAtP

	// Allow use of a default to decrease the length where possible
	targetIsSecure, ok := claims["sec"]
	if !ok {
		targetIsSecure = true
	}
	targetIsSecureB, ok := targetIsSecure.(bool)
	if !ok {
		rw.Write([]byte("is secure not bool\n"))
		http.Error(rw, "Forbidden", http.StatusForbidden)
		return
	}

	targetUrlScheme := "http"
	if targetIsSecureB {
		targetUrlScheme += "s"
	}
	targetUrl := &url.URL{
		Scheme: targetUrlScheme,
		Host:   host,
		Path:   targetUrlPath,
	}

	sessionDurationI := 0
	sessionDuration, ok := claims["ses"]
	if !ok {
		sessionDurationI = int(tokenExp.Time.Sub(tokenIssuedAt.Time))
	} else {
		sessionDurationF, ok := sessionDuration.(float64)
		if !ok {
			rw.Write([]byte("bad ses\n"))
			http.Error(rw, "Forbidden", http.StatusForbidden)
			return
		}
		sessionDurationI = int(sessionDurationF)
	}

	sessionTokenExp := time.Now().Add(time.Duration(sessionDurationI) * time.Second)
	sessionToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"exp": sessionTokenExp.Unix(),
		"iat": time.Now().Unix(),
		"iss": host,
	})

	signedSessionToken, err := sessionToken.SignedString([]byte(a.config.Secret))
	if err != nil {
		http.Error(rw, "Forbidden", http.StatusForbidden)
		return
	}

	http.SetCookie(rw, &http.Cookie{
		Name:    a.config.SessionCookie,
		Value:   signedSessionToken,
		Expires: sessionTokenExp,
		Path:    "/",
	})
	http.Redirect(rw, req, targetUrl.String(), http.StatusSeeOther)
}

func (a *JWTAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	path := req.URL.Path
	prefix := a.config.NormalizedPathPrefix()

	if !strings.HasPrefix(path, prefix) {
		if a.ValidateSession(rw, req) {
			a.next.ServeHTTP(rw, req)
		}
		return
	}

	pathSplit := strings.Split(path, prefix)
	if len(pathSplit) < 2 {
		a.next.ServeHTTP(rw, req)
		return
	}

	tokenString := pathSplit[1]
	a.HandleTokenUrl(rw, req, tokenString)
}
