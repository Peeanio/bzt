package api

import (
	"fmt"
	"log"
	"net/http"
	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
	"bzt-server/v2/data"
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

func Run() {
	route := gin.Default()

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
