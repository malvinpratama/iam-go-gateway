package router

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	authv1 "github.com/malvinpratama/iam-go-contracts/gen/auth/v1"
	"github.com/malvinpratama/iam-go-libs/config"
	"github.com/malvinpratama/iam-go-gateway/internal/middleware"
)

// ── browser session (stateless signed cookie) ───────────────

const sessionCookie = "iam_session"

func sessionSecret() []byte {
	return []byte(config.Getenv("SESSION_SECRET", "dev-session-secret-change-me-please"))
}

type session struct {
	UID   string `json:"uid"`
	Email string `json:"email"`
	Exp   int64  `json:"exp"`
}

func setSession(c *gin.Context, uid, email string) {
	payload, _ := json.Marshal(session{UID: uid, Email: email, Exp: time.Now().Add(time.Hour).Unix()})
	p := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, sessionSecret())
	mac.Write([]byte(p))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	secure := c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https"
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(sessionCookie, p+"."+sig, 3600, "/", "", secure, true)
}

func getSession(c *gin.Context) (session, bool) {
	raw, err := c.Cookie(sessionCookie)
	if err != nil {
		return session{}, false
	}
	parts := strings.SplitN(raw, ".", 2)
	if len(parts) != 2 {
		return session{}, false
	}
	mac := hmac.New(sha256.New, sessionSecret())
	mac.Write([]byte(parts[0]))
	want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(want), []byte(parts[1])) {
		return session{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return session{}, false
	}
	var s session
	if json.Unmarshal(payload, &s) != nil || s.Exp < time.Now().Unix() {
		return session{}, false
	}
	return s, true
}

// ── /authorize params ───────────────────────────────────────

type authzParams struct {
	ResponseType, ClientID, RedirectURI, Scope, State string
	CodeChallenge, CodeChallengeMethod, Nonce         string
}

func readParams(c *gin.Context, get func(string) string) authzParams {
	return authzParams{
		ResponseType:        get("response_type"),
		ClientID:            get("client_id"),
		RedirectURI:         get("redirect_uri"),
		Scope:               get("scope"),
		State:               get("state"),
		CodeChallenge:       get("code_challenge"),
		CodeChallengeMethod: get("code_challenge_method"),
		Nonce:               get("nonce"),
	}
}

func (p authzParams) values() url.Values {
	v := url.Values{}
	v.Set("response_type", p.ResponseType)
	v.Set("client_id", p.ClientID)
	v.Set("redirect_uri", p.RedirectURI)
	v.Set("scope", p.Scope)
	v.Set("state", p.State)
	v.Set("code_challenge", p.CodeChallenge)
	v.Set("code_challenge_method", p.CodeChallengeMethod)
	v.Set("nonce", p.Nonce)
	return v
}

func redirectError(c *gin.Context, p authzParams, code string) {
	sep := "?"
	if strings.Contains(p.RedirectURI, "?") {
		sep = "&"
	}
	loc := p.RedirectURI + sep + "error=" + url.QueryEscape(code)
	if p.State != "" {
		loc += "&state=" + url.QueryEscape(p.State)
	}
	c.Redirect(http.StatusFound, loc)
}

// ── handlers ────────────────────────────────────────────────

func (h *handlers) authorize(c *gin.Context) {
	p := readParams(c, c.Query)
	if p.ResponseType != "code" {
		c.Data(http.StatusBadRequest, "text/html; charset=utf-8", []byte("unsupported response_type (only 'code')"))
		return
	}
	client, err := h.c.Auth.GetClient(c.Request.Context(), &authv1.GetClientRequest{ClientId: p.ClientID})
	if err != nil {
		c.Data(http.StatusBadRequest, "text/html; charset=utf-8", []byte("unknown client"))
		return
	}
	if !contains(client.GetRedirectUris(), p.RedirectURI) {
		c.Data(http.StatusBadRequest, "text/html; charset=utf-8", []byte("invalid redirect_uri"))
		return
	}
	sess, ok := getSession(c)
	if !ok {
		c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(loginPage(p, "")))
		return
	}
	consent, _ := h.c.Auth.GetConsent(c.Request.Context(), &authv1.GetConsentRequest{UserId: sess.UID, ClientId: p.ClientID})
	if scopesCovered(consent.GetScopes(), strings.Fields(p.Scope)) {
		h.issueCode(c, p, sess.UID)
		return
	}
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(consentPage(p, client.GetName())))
}

func (h *handlers) authorizeLogin(c *gin.Context) {
	p := readParams(c, c.PostForm)
	tp, err := h.c.Auth.Login(c.Request.Context(), &authv1.LoginRequest{
		Email: c.PostForm("email"), Password: c.PostForm("password"),
	})
	if err != nil {
		c.Data(http.StatusUnauthorized, "text/html; charset=utf-8", []byte(loginPage(p, "Invalid email or password")))
		return
	}
	vt, err := h.c.Auth.ValidateToken(c.Request.Context(), &authv1.ValidateTokenRequest{AccessToken: tp.GetAccessToken()})
	if err != nil {
		c.Data(http.StatusInternalServerError, "text/html; charset=utf-8", []byte("login failed"))
		return
	}
	setSession(c, vt.GetUserId(), vt.GetEmail())
	c.Redirect(http.StatusFound, "/authorize?"+p.values().Encode())
}

func (h *handlers) authorizeConsent(c *gin.Context) {
	sess, ok := getSession(c)
	p := readParams(c, c.PostForm)
	if !ok {
		c.Redirect(http.StatusFound, "/authorize?"+p.values().Encode())
		return
	}
	if c.PostForm("action") != "allow" {
		redirectError(c, p, "access_denied")
		return
	}
	scopes := strings.Fields(p.Scope)
	_, _ = h.c.Auth.SaveConsent(c.Request.Context(), &authv1.SaveConsentRequest{UserId: sess.UID, ClientId: p.ClientID, Scopes: scopes})
	h.issueCode(c, p, sess.UID)
}

func (h *handlers) issueCode(c *gin.Context, p authzParams, uid string) {
	res, err := h.c.Auth.CreateAuthorizationCode(c.Request.Context(), &authv1.CreateAuthorizationCodeRequest{
		ClientId: p.ClientID, UserId: uid, RedirectUri: p.RedirectURI, Scope: p.Scope,
		CodeChallenge: p.CodeChallenge, CodeChallengeMethod: p.CodeChallengeMethod, Nonce: p.Nonce,
	})
	if err != nil {
		redirectError(c, p, "server_error")
		return
	}
	sep := "?"
	if strings.Contains(p.RedirectURI, "?") {
		sep = "&"
	}
	loc := p.RedirectURI + sep + "code=" + url.QueryEscape(res.GetCode())
	if p.State != "" {
		loc += "&state=" + url.QueryEscape(p.State)
	}
	c.Redirect(http.StatusFound, loc)
}

// clientCreds reads client_id/secret from the form (client_secret_post) or,
// failing that, HTTP Basic auth (client_secret_basic).
func clientCreds(c *gin.Context) (string, string) {
	id, secret := c.PostForm("client_id"), c.PostForm("client_secret")
	if id == "" {
		if u, p, ok := c.Request.BasicAuth(); ok {
			return u, p
		}
	}
	return id, secret
}

// token is the OAuth2 token endpoint (authorization_code + refresh_token grants).
func (h *handlers) token(c *gin.Context) {
	switch c.PostForm("grant_type") {
	case "authorization_code":
		id, secret := clientCreds(c)
		res, err := h.c.Auth.ExchangeAuthorizationCode(c.Request.Context(), &authv1.ExchangeAuthorizationCodeRequest{
			ClientId: id, ClientSecret: secret, Code: c.PostForm("code"),
			RedirectUri: c.PostForm("redirect_uri"), CodeVerifier: c.PostForm("code_verifier"),
		})
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant"})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"access_token": res.GetAccessToken(), "id_token": res.GetIdToken(),
			"refresh_token": res.GetRefreshToken(), "token_type": "Bearer",
			"expires_in": res.GetExpiresIn(), "scope": res.GetScope(),
		})
	case "refresh_token":
		tp, err := h.c.Auth.Refresh(c.Request.Context(), &authv1.RefreshRequest{RefreshToken: c.PostForm("refresh_token")})
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant"})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"access_token": tp.GetAccessToken(), "refresh_token": tp.GetRefreshToken(),
			"token_type": "Bearer", "expires_in": tp.GetExpiresIn(),
		})
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported_grant_type"})
	}
}

// userinfo is the OIDC UserInfo endpoint: returns claims for the bearer token.
func (h *handlers) userinfo(c *gin.Context) {
	id := middleware.IdentityOf(c)
	c.JSON(http.StatusOK, gin.H{"sub": id.UserID, "email": id.Email})
}

// registerClient registers a new OAuth client (admin only).
func (h *handlers) registerClient(c *gin.Context) {
	var body struct {
		Name         string   `json:"name" binding:"required"`
		RedirectURIs []string `json:"redirect_uris"`
		Scopes       []string `json:"scopes"`
		Confidential bool     `json:"confidential"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	res, err := h.c.Auth.RegisterClient(c.Request.Context(), &authv1.RegisterClientRequest{
		Name: body.Name, RedirectUris: body.RedirectURIs, Scopes: body.Scopes, IsConfidential: body.Confidential,
	})
	if err != nil {
		writeGRPCError(c, err)
		return
	}
	c.JSON(http.StatusCreated, gin.H{"client_id": res.GetClientId(), "client_secret": res.GetClientSecret()})
}

// ── helpers ─────────────────────────────────────────────────

func scopesCovered(granted, requested []string) bool {
	if len(requested) == 0 {
		return false
	}
	for _, r := range requested {
		if !contains(granted, r) {
			return false
		}
	}
	return true
}

// ── minimal HTML (no external assets) ───────────────────────

func hiddenFields(p authzParams) string {
	var b strings.Builder
	for k, vs := range p.values() {
		for _, v := range vs {
			fmt.Fprintf(&b, `<input type="hidden" name="%s" value="%s">`, html.EscapeString(k), html.EscapeString(v))
		}
	}
	return b.String()
}

const pageCSS = `<style>body{font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}
.card{background:#1e293b;padding:2rem 2.25rem;border-radius:14px;width:340px;box-shadow:0 10px 40px rgba(0,0,0,.4)}
h1{font-size:1.15rem;margin:0 0 .25rem}p{color:#94a3b8;font-size:.85rem;margin:.25rem 0 1.25rem}
label{display:block;font-size:.8rem;margin:.6rem 0 .2rem;color:#cbd5e1}
input[type=email],input[type=password]{width:100%;padding:.6rem .7rem;border:1px solid #334155;border-radius:8px;background:#0f172a;color:#e2e8f0;box-sizing:border-box}
button{margin-top:1.1rem;width:100%;padding:.65rem;border:0;border-radius:8px;background:#6366f1;color:#fff;font-weight:600;cursor:pointer}
button.ghost{background:#334155}.row{display:flex;gap:.6rem}.err{color:#f87171;font-size:.8rem;margin:.4rem 0}
.scopes{list-style:none;padding:0;margin:.5rem 0}.scopes li{padding:.35rem 0;border-bottom:1px solid #334155;font-size:.9rem}</style>`

func loginPage(p authzParams, errMsg string) string {
	e := ""
	if errMsg != "" {
		e = `<div class="err">` + html.EscapeString(errMsg) + `</div>`
	}
	return `<!doctype html><html><head><meta charset="utf-8"><title>Sign in · IAM</title>` + pageCSS + `</head><body>
<form class="card" method="post" action="/authorize/login">
<h1>🔐 Sign in to IAM</h1><p>An application is requesting access to your account.</p>` + e + `
<label>Email</label><input type="email" name="email" required autofocus>
<label>Password</label><input type="password" name="password" required>
` + hiddenFields(p) + `<button type="submit">Sign in</button></form></body></html>`
}

func consentPage(p authzParams, clientName string) string {
	var items strings.Builder
	for _, s := range strings.Fields(p.Scope) {
		fmt.Fprintf(&items, "<li>%s</li>", html.EscapeString(s))
	}
	return `<!doctype html><html><head><meta charset="utf-8"><title>Authorize · IAM</title>` + pageCSS + `</head><body>
<form class="card" method="post" action="/authorize/consent">
<h1>Authorize ` + html.EscapeString(clientName) + `</h1><p>This application wants access to:</p>
<ul class="scopes">` + items.String() + `</ul>` + hiddenFields(p) + `
<div class="row"><button class="ghost" type="submit" name="action" value="deny">Deny</button>
<button type="submit" name="action" value="allow">Allow</button></div></form></body></html>`
}
