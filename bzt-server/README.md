# bzt-server

## USAGE

```
go build
./bzt-server start
```

## Config file
`~/.bzt-server.yaml`
```
dbfile: "file:sqlite.db"
server_listen_port: "8080"
server_listen_cert: "/etc/ipsec.d/certs/domain.crt"
server_listen_key: "/etc/ipsec.d/private/domain.key"
```

## DB Schema
```
CREATE TABLE agents(ID int primary key, Token, Expiry);
CREATE TABLE tokens(Token text primary key, Username text, Expiry int);
CREATE TABLE connections(UUID text primary key, Username text, Connection text, Source text, PeerID text, Expiry int);
```
