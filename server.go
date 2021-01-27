package main

import (
	"io"
	"net/http"
	"net/url"
	"os"
	"bytes"
	"html/template"
	"encoding/gob"

	"golang.org/x/oauth2"
	"golang.org/x/net/context"
	oidc "github.com/coreos/go-oidc/v3/oidc"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/labstack/gommon/log"
	"github.com/thanhpk/randstr"

	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"
)

var (
	oauthConfig *oauth2.Config
	clientID         = os.Getenv("CLIENT_ID")
        clientSecret     = os.Getenv("CLIENT_SECRET")
	oauthStateString = randstr.Hex(16)
	templatesDir     = "templates"
	oneLoginBaseUrl  = "https://openid-connect.onelogin.com"
	callbackUrl      = "http://localhost:8080/callback"
	sessionStore     = "onelogin-demo-secret"
)

type TemplateRenderer struct {
	templates *template.Template
}

func (t *TemplateRenderer) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	return t.templates.ExecuteTemplate(w, name, data)
}

type Authenticator struct {
	Provider *oidc.Provider
	Config   oauth2.Config
	Ctx      context.Context
}

var authenticator *Authenticator

func init() {
	ctx := context.Background()

	provider, err := oidc.NewProvider(ctx, oneLoginBaseUrl + "/oidc")
	if err != nil {
		log.Fatal(err)
	}

	conf := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  callbackUrl,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile"},
	}

	authenticator = &Authenticator{
		Provider: provider,
		Config:   conf,
	}
}

func main() {
	e := echo.New()

	renderer := &TemplateRenderer{
		templates: template.Must(template.ParseGlob(templatesDir + "/*.html")),
	}
	e.Renderer = renderer

	// Enable HTTP requests logging
	e.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{
		Format: `{"time":"${time_rfc3339}","method":"${method}","uri":"${uri}","status":${status},"error":"${error}"}` + "\n",
	}))

	// Enable sessions storage on server-side
	e.Use(session.Middleware(sessions.NewFilesystemStore("", []byte(sessionStore))))
	gob.Register(map[string]interface{}{})

	e.GET("/", rootHandler)
	e.GET("login", loginHandler)
	e.GET("/callback", callbackHandler)
	e.GET("/userinfo", userinfoHandler, isAuthenticated)
	e.GET("/logout", logoutHandler)

	e.Logger.Fatal(e.Start(":8080"))
}

func isAuthenticated(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		sess, err := session.Get("onelogin-session", c)
		if err != nil {
			log.Error("Invalid auth session")
			return c.Redirect(http.StatusInternalServerError, "/")
		}

		if _, ok := sess.Values["userinfo"]; !ok {
			log.Error("User is not logged in")
			c.Redirect(http.StatusSeeOther, "/")
		}
		return next(c)
	}
}

func rootHandler(c echo.Context) error {
	return c.Render(http.StatusOK, "login.html", "")
}

func loginHandler(c echo.Context) error {
	sess, err := session.Get("onelogin-session", c)
	if err != nil {
		log.Error("Invalid auth session")
		return c.Redirect(http.StatusInternalServerError, "/")
	}

	sess.Values["state"] = oauthStateString

	err = sess.Save(c.Request(), c.Response())
	if err != nil {
		log.Error("Cannot save session: ", err.Error())
		return c.Redirect(http.StatusInternalServerError, "/")
	}

	url := authenticator.Config.AuthCodeURL(oauthStateString)
	return c.Redirect(http.StatusTemporaryRedirect, url)
}

func callbackHandler(c echo.Context) error {
	sess, err := session.Get("onelogin-session", c)
	if err != nil {
		log.Error("Invalid auth session")
		return c.Redirect(http.StatusInternalServerError, "/")
	}

	state := c.FormValue("state")
	//log.Infof("OneLogin response State: %s", state)

	code := c.FormValue("code")
	//log.Infof("OneLogin response Code: %s", code)

	if state != oauthStateString {
		log.Error("Invalid oauth state")
		return c.Redirect(http.StatusBadRequest, "/")
	}

	// Get Token by Response Code
	token, err := authenticator.Config.Exchange(context.TODO(), code)
	if err != nil {
		log.Error("Code exchange failed: ", err.Error())
		return c.Redirect(http.StatusInternalServerError, "/")
	}
	//log.Infof("Access token: %s", token.Extra("access_token"))
	//log.Infof("Refresh token: %s", token.Extra("refresh_token"))
	//log.Infof("ID token: %s", token.Extra("id_token"))

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		log.Error("No id_token field in oauth2 token: ", err.Error())
		return c.Redirect(http.StatusInternalServerError, "/")
	}

	oidcConfig := &oidc.Config{
		ClientID: clientID,
	}
	idToken, err := authenticator.Provider.Verifier(oidcConfig).Verify(context.TODO(), token.Extra("id_token").(string))
	if err != nil {
		log.Error("Failed to verify ID token: ", err.Error())
		return c.Redirect(http.StatusInternalServerError, "/")
	}

        var userinfo map[string]interface{}
	if err := idToken.Claims(&userinfo); err != nil {
		c.Logger().Error(err)
		return c.Redirect(http.StatusInternalServerError, "/")
	}

	sess.Values["id_token"] = rawIDToken
	sess.Values["access_token"] = token.AccessToken
	sess.Values["userinfo"] = userinfo

	err = sess.Save(c.Request(), c.Response())
	if err != nil {
		log.Error("Cannot save session: ", err.Error())
		return c.Redirect(http.StatusInternalServerError, "/")
	}

	return c.Redirect(http.StatusSeeOther, "/userinfo")
}

func userinfoHandler(c echo.Context) error {
        sess, err := session.Get("onelogin-session", c)
        if err != nil {
                log.Error("Invalid auth session")
                return c.Redirect(http.StatusInternalServerError, "/")
        }

        return c.Render(http.StatusOK, "userinfo.html", sess.Values["userinfo"])
}

func logoutHandler(c echo.Context) error {
	// Clear server session. In case of Filesystem Store, set MaxAge < 0
	sess, err := session.Get("onelogin-session", c)
	if err != nil {
		log.Error("Invalid auth session")
		return c.Redirect(http.StatusInternalServerError, "/")
	}
	access_token := sess.Values["access_token"].(string)
	sess.Options = &sessions.Options{
		MaxAge: -1,
	}
	sess.Save(c.Request(), c.Response())

	// Revoke access token
	params := url.Values{}
	params.Add("token", access_token)
	params.Add("token_type_hint", "access_token")
	params.Add("client_id", clientID)
	params.Add("client_secret", clientSecret)

	text := []byte(params.Encode())
	responseBody := bytes.NewBuffer(text)

	resp, err := http.Post(oneLoginBaseUrl + "/oidc/token/revocation", "application/x-www-form-urlencoded", responseBody)
	if err != nil {
		log.Fatalf("An Error Occured during Access Token Revocation: %v", err)
	}
	log.Infof("OneLogin Access token revocation response: %v", resp)

	// If you want to logout user at all, you could call an api endpoint.
	// You need another access_token for that (<access_token_for_api> below):
	// 1. Register API Credentials in OneLogin Admin page. Grab <CLIENT_ID> and <CLIENT_SECRET>
	// 2. Having them, receive <access_token_for_api> in this way:
	//    $ curl 'https://api.us.onelogin.com/auth/oauth2/token' -X POST -H "Authorization: client_id:<CLIENT_ID>, client_secret:<CLIENT_SECRET>" -H "Content-Type: application/json" -d '{"grant_type":"client_credentials" }'
	// 3. Above command will return an <access_token_for_api> that you can later for api-calls
	// 4. API call to logout user, for instance:
	//    $ curl https://api.us.onelogin.com/api/1/users/<user_id>/logout -XPUT -H "Authorization: bearer: <access_token_for_api>"
	// 5. Example of code for the step 4 is below.
	//
	//req, err := http.NewRequest("PUT", "https://api.us.onelogin.com/api/1/users/<user_id>/logout", bytes.NewBuffer([]byte("")))
	//if err != nil {
	//	log.Fatalf("An Error Occured during Logout Request Preparation: %v", err)
	//}
	//req.Header.Set("Authorization", "bearer: " + <access_token_for_api>)
	//
	//log.Infof("HTTP Logout Request: %v", req)
	//
	//response, err := http.DefaultClient.Do(req)
	//if err != nil {
	//	log.Fatalf("An Error Occured during Logout Request: %v", err)
	//}
	//
	//log.Infof("OneLogin logout response: %v", response)

        return c.Redirect(http.StatusTemporaryRedirect, "/")
}
