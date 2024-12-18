package api

import (
	"fmt"
	"log"
	"net/http"
	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
	"bzt-server/v2/data"

	"io"
	"encoding/base64"
	"crypto/rand"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-contrib/sessions"
)

var (
	oauth2State = ""
	oauth_config = oauth2.Config{}
)

type ClientAuthRequest struct {
	Token string `json:"token"`
	Endpoint string `json:"endpoint"`
	PeerId string `json:"peerid"`
}

func err_check(e error) {
	if e != nil {
		log.Println(e)
	}
}

func randString(nByte int) (string, error) {
	b := make([]byte, nByte)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func Run() {
	route := gin.Default()
	ctx := context.Background()
	oauth2State = viper.GetString("oauth_state_secret")
	provider, err := oidc.NewProvider(ctx, viper.GetString("oauth_provider_endpoint"))
	if err != nil {
		log.Println("provider err ", err)
	}
	oauth_config = oauth2.Config{
		ClientID: "bzt",
		ClientSecret: viper.GetString("oauth_client_secret"),
		Endpoint: provider.Endpoint(),
		RedirectURL: viper.GetString("oauth_redirect_url"),
		Scopes: []string{oidc.ScopeOpenID, "profile", "email"},
	}
	store := cookie.NewStore([]byte("secret"))
	route.Use(sessions.Sessions("mysession", store))

	route.GET("/auth/login", func(c *gin.Context) {
		url := oauth_config.AuthCodeURL(oauth2State, oauth2.AccessTypeOffline)
		c.Redirect(http.StatusFound, url)
	})
	route.GET("/auth/callback", callbackHandler)
	route.GET("/prot", requireSession, postClientAuthorize)

	route.GET("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "pong",
		})
	})
	route.POST("/client/authorize", postClientAuthorize)
	route.GET("/agent/connections", getAgentConnections)
	if viper.IsSet("server_listen_cert") && viper.IsSet("server_listen_key") {
		route.RunTLS(fmt.Sprintf(":%s",viper.GetString("server_listen_port")), viper.GetString("server_listen_cert"), viper.GetString("server_listen_key"))
	} else {
		route.Run(fmt.Sprintf(":%s", viper.GetString("server_listen_port")))
	}
}

func callbackHandler(c *gin.Context) {
	code := c.DefaultQuery("code", "")
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No code provided"})
		return
	}
	state := c.DefaultQuery("state", "")
	if state != oauth2State {
		c.JSON(http.StatusBadRequest, gin.H{"error": "State invalid"})
		return
	}

	// Exchange the code for a token
	token, err := oauth_config.Exchange(c, code)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to exchange token"})
		return
	}

	// Save the token in a global variable or session store
	session := sessions.Default(c)
	session.Set("token", token.AccessToken)
	session.Save()

	c.JSON(http.StatusOK, gin.H{
		"message": "Login successful!",
		"token":   token.AccessToken,
		"token_string": token,
	})
}

func loginHandler(c *gin.Context) {
	url := oauth_config.AuthCodeURL(oauth2State, oauth2.AccessTypeOffline)
	c.Redirect(http.StatusFound, url)
}

// requireSession is a middleware to check if the user is authenticated
func requireSession(c *gin.Context) {
	session := sessions.Default(c)
	token := session.Get("token")
	if token == nil {
		// If there is no token in the session, the user is not authenticated
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		c.Abort()
		return
	}
	// Allow the request to continue
	c.Next()
}

// profileHandler returns the user's profile information (protected route)
func profileHandler(c *gin.Context) {
	// Retrieve the token from the session
	session := sessions.Default(c)
	token := session.Get("token")

	// // Use the OAuth2 token to make a request to the OAuth2 provider (Google in this case)
	// client := oauth2Config.Client(c, token)
	// resp, err := client.Get("https://www.googleapis.com/oauth2/v1/userinfo?alt=json")
	// if err != nil {
	// 	c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
	// 	return
	// }
	// defer resp.Body.Close()
 //
	// var userInfo map[string]interface{}
	// if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
	// 	c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to decode user info"})
	// 	return
	// }

	// Return user profile information
	c.JSON(http.StatusOK, gin.H{
		"okay": true,
		"token": token,
		// "email":    userInfo["email"],
		// "name":     userInfo["name"],
		// "picture":  userInfo["picture"],
	})
}

func getAgentConnections(c *gin.Context) {
	token, err := c.Cookie("token")
	user, err := c.Cookie("id")
	if err != nil {
		log.Println(err)
		c.JSON(http.StatusUnauthorized, gin.H{
			"authorized":"failed",
		})
	} else {
		valid, err := data.CheckAgentToken(token)
		if err != nil {
			log.Println(err)
			c.JSON(http.StatusUnauthorized, gin.H{
				"authorized":"failed",
			})
		} else {
			if valid {
				var connections []data.AgentConnectionTableEntry
				connections, err := data.ReadConnections()
				if err != nil {
					log.Println(err)
					c.JSON(http.StatusUnauthorized, gin.H{
						"authorized":"failed",
					})
				} else {
					if err != nil {
						log.Println(err)
						c.JSON(http.StatusUnauthorized, gin.H{
							"authorized":"failed",
						})
					} else {
						c.JSON(http.StatusOK, gin.H{
							"authorized":"successful",
							"user": user,
							"rules": connections,
						})
					}
				}
			} else {
				log.Println(err)
				c.JSON(http.StatusUnauthorized, gin.H{
					"authorized":"failed",
				})
			}
		}
	}

}

func postClientAuthorize(c *gin.Context) {
	var request ClientAuthRequest
	err := c.BindJSON(&request)
	if err != nil {
		log.Println(err)
		c.JSON(http.StatusUnauthorized, gin.H{
			"authorized":"failed",
		})
	}
	sourceIP := c.ClientIP()
	valid, tokenEntry, err := data.CheckClientToken(request.Token)
	if err != nil {
		log.Println(err)
		c.JSON(http.StatusUnauthorized, gin.H{
			"authorized":"failed",
		})
	} else {
		if valid {
			tm, err := data.UnixToTime(tokenEntry.Expiry)
			if err != nil {
				log.Println(err)
				c.JSON(http.StatusUnauthorized, gin.H{
					"authorized":"failed",
				})
			} else {
				err = data.AllowConnection(tokenEntry.Username, request.Endpoint, sourceIP, request.PeerId, tm)
				if err != nil {
					log.Println(err)
					c.JSON(http.StatusUnauthorized, gin.H{
						"authorized":"failed",
					})
				} else {
					c.JSON(http.StatusOK, gin.H{
						"authorized":"successful",
						"expiry": tokenEntry.Expiry,
						"sourceIp": sourceIP,
					})
				}
			}
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{
				"authorized":"failed",
			})
		}
	}
}
