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

func create_conn_file(conn AgentConnectionTableEntry) (bool, error) {
	file_path := fmt.Sprintf("%s/%s.conf", ipsec_conf_path, conn.UUID)
	dest_ip := strings.Split(conn.Destination, ":")[0]
	if _, err := os.Stat(file_path); err == nil {
		return false, nil//errors.New(fmt.Sprintf("Not creating conf file for %s, connection file exists!", conn.UUID))
	} else if errors.Is(err, os.ErrNotExist) {
		conf_file, err := os.Create(file_path)
		if err != nil {
			return false, err
		}
		defer conf_file.Close()
		_, err = fmt.Fprintf(conf_file,
			    "conn %s\n\ttype=transport\n\tauthby=secret\n\tleft=%s\n\tright=%s\n\tpfs=yes\n\tauto=start\n",
			    conn.UUID,
			    conn.Source,
			    dest_ip)

		if err != nil {
			return false, err
		}
		fmt.Printf("wrote %s conf file\n", conn.UUID)
		return true, nil
	} else {
		return false, errors.New("connection file in undetermined state, could not create")
	}
}

func reload_ipsec() error {
	cmd := exec.Command("ipsec", "reload")
	var out strings.Builder
	cmd.Stderr = &out
	err := cmd.Run()
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
	fmt.Printf("added %s iptables rule\n", conn.UUID)
	return nil
}

func check_if_conn_in_table(conn AgentConnectionTableEntry) bool {
	cmd := exec.Command("iptables", "-L", "-v")
	var out strings.Builder
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return false//, err
	}
	if strings.Contains(out.String(), conn.UUID) {
		return true
	}
	return false//, err
}

func do_connections(conf AgentClientConfig){
	conns, err := getConnections(conf)
	if err != nil {
		log.Fatal(err)
	}
	for _, v := range conns {
		changed, err := create_conn_file(v)
		if err != nil {
			fmt.Println(err)
			continue
		}
		if changed {
			err = reload_ipsec()
			if err != nil {
				fmt.Println(err)
			}
		}
		allowed  := check_if_conn_in_table(v)
		// if err != nil {
		// 	fmt.Println(err)
		// 	continue
		// }
		if allowed != true {
			err = allow_connection(v)
			if err != nil {
				fmt.Println(err)
			}
		}

	}
}

func start_ipsec() error {
	cmd := exec.Command("systemctl", "start", "ipsec")
	err := cmd.Run()
	if err != nil {
		return err
	}
	return nil
}

func ipsec_default_drop() error {
	cmd := exec.Command("ip", "xfrm", "policy", "setdefault", "in", "block")
	err := cmd.Run()
	if err != nil {
		return err
	}
	return nil
}

func run_command_with_out(c *exec.Cmd) (strings.Builder, error) {
	var out strings.Builder
	c.Stdout = &out
	c.Stderr = &out
	err := c.Run()
	if err != nil {
		return out, err
	}
	return out, nil
}

func iptables_default_drop() error {
	cmd := exec.Command("iptables", "-P", "INPUT", "DROP")
	out, err := run_command_with_out(cmd)
	if err != nil {
		fmt.Println(out.String())
		return err
	}
	cmd = exec.Command("iptables", "-A", "INPUT", "-p", "esp", "-j", "ACCEPT")
	out, err = run_command_with_out(cmd)
	if err != nil {
		fmt.Println(out.String())
		return err
	}
	cmd = exec.Command("iptables", "-A", "INPUT", "-p", "udp", "--dport", "4500", "-j", "ACCEPT")
	out, err = run_command_with_out(cmd)
	if err != nil {
		fmt.Println(out.String())
		return err
	}
	cmd = exec.Command("iptables", "-A", "INPUT", "-p", "udp", "--dport", "500", "-j", "ACCEPT")
	out, err = run_command_with_out(cmd)
	if err != nil {
		fmt.Println(out.String())
		return err
	}
	return nil
}

func first_run() {
	err := start_ipsec()
	if err != nil {
		log.Fatalf("ipsec start %s", err)

	}
	err = ipsec_default_drop()
	if err != nil {
		log.Fatalf("ipsec default %s", err)

	}
	err = iptables_default_drop()
	if err != nil {
		log.Fatal("iptables setup %s", err)

	}

}

func Run(conf AgentClientConfig) {
	first_run()
	for {
		time.Sleep(time.Second * 30)
		go do_connections(conf)
		fmt.Println("looping")
	}
}
