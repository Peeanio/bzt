package agent

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"time"
	"strings"
	"strconv"
	"encoding/json"
	"net/http"
	"os/exec"
	"github.com/spf13/viper"
	// "bzt-server/v2/data"
)

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
	PeerId string `json:"peerid"`
	Expiry int `json:"expiry"`
}

func UnixToTime(epoch int) (time.Time, error) {
	t := strconv.Itoa(epoch)
	i, err := strconv.ParseInt(t, 10, 64)
	if err != nil {
		return time.Unix(0, 0), err
	}
	tm := time.Unix(i, 0)
	return tm, nil
}

func getConnections(clientConfig AgentClientConfig, endpoint string) ([]AgentConnectionTableEntry, error) {
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
			    "conn %s\n\ttype=transport\n\tauthby=pubkey\n\tleft=%s\n\tright=%s\n\tleftcert=%s\n\tauto=start\n\trightid=\"%s\"",
			    conn.Source,
			    conn.UUID,
			    viper.GetString("cert"),
			    dest_ip,
			    conn.PeerId)

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
	cmd := exec.Command("iptables", "-A", "INPUT", "-s", source, "-p", proto, "--dport", port, "-j", "ACCEPT", "-m", "comment", "--comment", fmt.Sprintf("%s|%d", conn.UUID, conn.Expiry))
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
	cmd := exec.Command("iptables", "-L", "-v", "-n")
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

// func check_if_conn_in_table2(conn AgentConnectionTableEntry) bool {
// 	split := strings.Split(conn.Destination, ":")
// 	proto := split[0]
// 	port := split[len(split)-1]
// 	source := conn.Source
// 	cmd := exec.Command("iptables", "-C", "INPUT", "-s", source, "-p", proto, "--dport", port, "-j", "ACCEPT", "-m", "comment", "--comment", fmt.Sprintf("%s|%d", conn.UUID, conn.Expiry))
// 	err := cmd.Run()
// 	if err != nil {
// 		return false//, err
// 	}
// 	if strings.Contains(out.String(), conn.UUID) {
// 		return true
// 	}
// 	return false//, err
// }

func do_connections(conns []AgentConnectionTableEntry){
	for _, v := range conns {
		unix_exp, err := UnixToTime(v.Expiry)
		if err != nil {
			fmt.Println(err)
			continue
		}
		if time.Now().Before(unix_exp) {
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
}

func do_cleanup(conns []AgentConnectionTableEntry){
	for _, v := range conns {
		unix_exp, err := UnixToTime(v.Expiry)
		if err != nil {
			fmt.Println(err)
			continue
		}
		if time.Now().After(unix_exp) {
			changed, err := remove_conn_file(v)
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
			allowed := check_if_conn_in_table(v)
			if allowed == true {
				err = remove_connection(v)
				if err != nil {
					fmt.Println(err)
				}
			}
		}

	}
}

func remove_conn_file(conn AgentConnectionTableEntry) (bool, error) {
	file_path := fmt.Sprintf("%s/%s.conf", ipsec_conf_path, conn.UUID)
	_, err := os.Stat(file_path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	err = os.Remove(file_path)
	if err != nil {
		log.Println(err)
		return false, err
	}
	log.Println("removed %s", file_path)
	return true, nil
}

func remove_connection(conn AgentConnectionTableEntry) error {
	split := strings.Split(conn.Destination, ":")
	proto := split[0]
	port := split[len(split)-1]
	source := conn.Source
	cmd := exec.Command("iptables", "-D", "INPUT", "-s", source, "-p", proto, "--dport", port, "-j", "ACCEPT", "-m", "comment", "--comment", fmt.Sprintf("%s|%d", conn.UUID, conn.Expiry))
	var out strings.Builder
	cmd.Stderr = &out
	err := cmd.Run()
	if err != nil {
		return errors.New(fmt.Sprintf("%s %s", err, out.String()))
	}
	fmt.Printf("removed %s iptables rule\n", conn.UUID)
	return nil
}
func ensure_include_for_ipsec() error {
	file, err := os.OpenFile("/etc/ipsec.conf", os.O_APPEND|os.O_RDWR, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// optionally, resize scanner's capacity for lines over 64K, see next example
	var present bool
	for scanner.Scan() {
		line := scanner.Text()
		if contains := strings.Contains(line, "include /etc/ipsec.conf.d/*.conf"); contains {
			present = true
			continue
		}
	}
	if !present {
		log.Println("writing config include")
		if _, err := file.WriteString("include /etc/ipsec.conf.d/*.conf\n"); err != nil {
			return err
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
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
	cmd = exec.Command("iptables", "-C", "INPUT", "-p", "esp", "-j", "ACCEPT")
	out, err = run_command_with_out(cmd)
	if err != nil {
		if strings.Contains(out.String(), "iptables: Bad rule (does a matching rule exist in that chain?).") == true {
			cmd = exec.Command("iptables", "-A", "INPUT", "-p", "esp", "-j", "ACCEPT")
			out, err = run_command_with_out(cmd)
			if err != nil {
				fmt.Println(out.String())
				return err
			}
		} else {
			fmt.Println(out.String())
			return err
		}
	}
	cmd = exec.Command("iptables", "-C", "INPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT")
	out, err = run_command_with_out(cmd)
	if err != nil {
		fmt.Println(out.String())
		if strings.Contains(out.String(), "iptables: Bad rule (does a matching rule exist in that chain?).") == true {
			cmd = exec.Command("iptables", "-A", "INPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT")
			out, err = run_command_with_out(cmd)
			if err != nil {
				fmt.Println(out.String())
				return err
			}
		} else {
			fmt.Println(out.String())
			return err
		}
	}
	cmd = exec.Command("iptables", "-C", "INPUT", "-p", "udp", "--dport", "4500", "-j", "ACCEPT")
	out, err = run_command_with_out(cmd)
	if err != nil {
		fmt.Println(out.String())
		if strings.Contains(out.String(), "iptables: Bad rule (does a matching rule exist in that chain?).") == true {
			cmd = exec.Command("iptables", "-A", "INPUT", "-p", "udp", "--dport", "4500", "-j", "ACCEPT")
			out, err = run_command_with_out(cmd)
			if err != nil {
				fmt.Println(out.String())
				return err
			}
		} else {
			fmt.Println(out.String())
			return err
		}
	}
	cmd = exec.Command("iptables", "-C", "INPUT", "-p", "udp", "--dport", "500", "-j", "ACCEPT")
	out, err = run_command_with_out(cmd)
	if err != nil {
		fmt.Println(out.String())
		if strings.Contains(out.String(), "iptables: Bad rule (does a matching rule exist in that chain?).") == true {

			cmd = exec.Command("iptables", "-A", "INPUT", "-p", "udp", "--dport", "500", "-j", "ACCEPT")
			out, err = run_command_with_out(cmd)
			if err != nil {
				fmt.Println(out.String())
				return err
			}
		} else {
			fmt.Println(out.String())
			return err
		}
	}
	return nil
}

func first_run() {
	err := ensure_include_for_ipsec()
	if err != nil {
		log.Fatalf("ipsec config include set %s", err)

	}
	err = start_ipsec()
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

	_, err = create_conn_file(AgentConnectionTableEntry{
		"bzt-server",
		"",
		"",
		"%any",
		viper.GetString("serverpeerid"),
		9999999999999,
	})
	if err != nil {
		log.Fatal("peer connection to server failed %s", err)

	}

}

func Run(conf AgentClientConfig) {
	first_run()
	for {
		conns, err := getConnections(conf, viper.GetString("server"))
		if err != nil {
			log.Fatal(err)
		}
		go do_connections(conns)
		go do_cleanup(conns)
		time.Sleep(time.Second * 30)
		log.Println("looping")
	}
}
