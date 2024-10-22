package agent

import (
	"fmt"
	"log"
	"time"
	"strings"
	"net/http"
	// "bzt-server/v2/data"
)

const endpoint = "http://127.0.0.1:8080"

type AgentClientConfig struct {

}
type AgentConnectionTableEntry struct {
	UUID string `json:"uuid"`
	Username string `json:"username"`
	Destination string `json:"destination"`
	Source string `json:"source"`
	Expiry int `json:"expiry"`
}

func getConnections(client_config AgentClientConfig) ([]AgentConnectionTableEntry, error) {
	var connections []AgentConnectionTableEntry
	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	req, err := http.NewRequestWithContext(context.Background(),
					       http.MethodGet, strings.Join([]string{endpoint, "/agent/connections"}, ""), nil)
	if err != nil {
		return connections, err
	}

}

func Run() {
	conns, err := getConnections
	if err != nil {
		log.Fatal(err)
	}
	for conns.Next() {
		var conn AgentConnectionTableEntry
		fmt.Println(conn)
	}
}
