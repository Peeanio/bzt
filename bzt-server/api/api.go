package api

import (
	//"fmt"
	"log"
	"net/http"
	"github.com/gin-gonic/gin"
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

	route.Run(":8080")
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
