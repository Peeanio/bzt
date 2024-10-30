package agent

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"time"
	"strings"
	"encoding/json"
	"net/http"
	"os/exec"
	// "bzt-server/v2/data"
)

const endpoint = "http://127.0.0.1:8080"
const ipsec_conf_path = "/etc/ipsec.conf.d"

type AgentClientConfig struct {
	Cookies []http.Cookie
}

type AgentConnectionTableReply struct {
	Authorized string `json:"authorized"`
	Rules []AgentConnectionTableEntry `json:"rules"`
}

type AgentConnectionTableEntry struct {
	UUID string `json:"uuid"`
	Username string `json:"username"`
	Destination string `json:"destination"`
	Source string `json:"source"`
	Expiry int `json:"expiry"`
}

func getConnections(clientConfig AgentClientConfig) ([]AgentConnectionTableEntry, error) {
	var connections []AgentConnectionTableEntry
	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	req, err := http.NewRequest(http.MethodGet, strings.Join([]string{endpoint, "/agent/connections"}, ""), nil)
	if err != nil {
		return connections, err
	}
	for _, v := range clientConfig.Cookies {
		req.AddCookie(&v)
	}
	res, err := client.Do(req)
	if err != nil {
		return connections, err
	}
	// log.Println(res)
	body, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		return connections, err
	}
	// fmt.Println(body)
	// fmt.Println(string(body))
	var reply AgentConnectionTableReply
	err = json.Unmarshal(body, &reply)
	if err != nil {
		return connections, err
	}
	// fmt.Println(reply)
	for _, v := range reply.Rules {
		connections = append(connections, v)
	}
	// fmt.Println(connections)
	return connections, nil

}

func create_conn_file(conn AgentConnectionTableEntry) error {
	file_path := fmt.Sprintf("%s/%s.conf", ipsec_conf_path, conn.UUID)
	dest_ip := strings.Split(conn.Destination, ":")[0]
	if _, err := os.Stat(file_path); err == nil {
		return errors.New("connection file exists")
	} else if errors.Is(err, os.ErrNotExist) {
		conf_file, err := os.Create(file_path)
		if err != nil {
			return err
		}
		defer conf_file.Close()
		_, err = fmt.Fprintf(conf_file,
			    "conn %s\n\ttype=transport\n\tauthby=secret\n\tleft=%s\n\tright=%s\n\tpfs=yes\n\tauto=start\n",
			    conn.UUID,
			    conn.Source,
			    dest_ip)

		if err != nil {
			return err
		}
		return nil
	} else {
		return errors.New("connection file in undetermined state, could not create")
	}
}

func reload_ipsec() error {
	cmd := exec.Command("ipsec", "reload")
	var out strings.Builder
	cmd.Stderr = &out
	err := cmd.Run()
	// fmt.Println(out.String())
	if err != nil {
		return errors.New(fmt.Sprintf("%s %s", err, out.String()))
	}
	return nil
}

func allow_connection(conn AgentConnectionTableEntry) error {
	split := strings.Split(conn.Destination, ":")
	proto := split[0]
	port := split[len(split)-1]
	source := conn.Source
	cmd := exec.Command("iptables", "-A", "INPUT", "-s", source, "-p", proto, "--dport", port, "-j", "ACCEPT", "-m", "comment", "--comment", conn.UUID)
	var out strings.Builder
	cmd.Stderr = &out
	err := cmd.Run()
	if err != nil {
		return errors.New(fmt.Sprintf("%s %s", err, out.String()))
	}
	return nil
}

func Run(conf AgentClientConfig) {
	conns, err := getConnections(conf)
	if err != nil {
		log.Fatal(err)
	}
	for _, v := range conns {
		err := create_conn_file(v)
		if err != nil {
			fmt.Println(err)
		}
		err = reload_ipsec()
		if err != nil {
			fmt.Println(err)
		}
		err = allow_connection(v)
		if err != nil {
			fmt.Println(err)
		}

	}
}
