package data

import (
	//"fmt"
	"errors"
	"log"
	"time"
	"strconv"
	"database/sql"
	"github.com/google/uuid"
	_ "github.com/ncruces/go-sqlite3/driver"
	_ "github.com/ncruces/go-sqlite3/embed"
)

const fileName = "file:sqlite.db"
const tokenTable = "tokens"
const connTable = "connections"

type ClientTokenTableEntry struct {
	Token string
	Username string
	Expiry int //unix time integer
}

type AgentTokenTableEntry struct {
	Token string
	ID string
	Expiry int //unix time integer
}

type AgentConnectionTableEntry struct {
	UUID string `json:"uuid"`
	Username string `json:"username"`
	Destination string `json:"destination"`
	Source string `json:"source"`
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

func CheckAgentToken(token string) (bool, error) {
	db, err := sql.Open("sqlite3", fileName)
	if err != nil {
		log.Print(err)
		return false, err
	}
	var tokenEntry AgentTokenTableEntry
	err = db.QueryRow("SELECT Token, ID, Expiry FROM agents WHERE token = ?", token).Scan(&tokenEntry.Token, &tokenEntry.ID, &tokenEntry.Expiry)
	if err != nil {
		log.Print(err)
		return false, err
	}
	exp, err := UnixToTime(tokenEntry.Expiry)
	if err != nil {
		log.Print(err)
		return false, err
	}
	if time.Now().After(exp) {
		return false, errors.New("token expired")
	} else {
		return true, nil
	}
}

func CheckClientToken(tokenValue string) (bool, ClientTokenTableEntry, error) {
	db, err := sql.Open("sqlite3", fileName)
	if err != nil {
		log.Print(err)
		return false,
			ClientTokenTableEntry{
				Token: "",
				Username: "",
				Expiry: 0,
			},
			err
	}
	var tokenEntry ClientTokenTableEntry
	err = db.QueryRow("SELECT Token, Username, Expiry FROM tokens WHERE token = ?", tokenValue).Scan(&tokenEntry.Token, &tokenEntry.Username, &tokenEntry.Expiry)
	if err != nil {
		log.Print(err)
		return false,
			ClientTokenTableEntry{
				Token: "",
				Username: "",
				Expiry: 0,
			},
			err
	}
	exp, err := UnixToTime(tokenEntry.Expiry)
	if err != nil {
		log.Print(err)
		return false,
			ClientTokenTableEntry{
				Token: "",
				Username: "",
				Expiry: 0,
			},
			err
	}
	if time.Now().After(exp) {
		return false, tokenEntry, nil
	} else {
		return true, tokenEntry, nil
	}
}

func AllowConnection(username string, connection string, source string, expiry time.Time) error {
	db, err := sql.Open("sqlite3", fileName)
	if err != nil {
		log.Print(err)
		return err
	}
	uuid := uuid.New()
	if err != nil {
		log.Print(err)
		return err
	}
	result, err := db.Exec("INSERT INTO connections values(?, ?, ?, ?, ?);", uuid, username, connection, source, expiry.Unix())
	log.Print(result)
	if err != nil {
		log.Print(err)
		return err
	}
	return nil
}

func ReadConnections() ([]AgentConnectionTableEntry, error) {
	var connections []AgentConnectionTableEntry
	db, err := sql.Open("sqlite3", fileName)
	if err != nil {
		return connections, nil
	}
	rows, err := db.Query("SELECT * from connections")
	if err != nil {
		return connections, err
	} else {
		for rows.Next() {
			var row AgentConnectionTableEntry
			if err := rows.Scan(&row.UUID, &row.Username, &row.Destination, &row.Source, &row.Expiry); err != nil {
				return connections, err
			}
			connections = append(connections, row)
		}
		return connections, nil
	}
}
