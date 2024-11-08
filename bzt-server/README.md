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
```

## DB Schema
```
CREATE TABLE agents(ID int primary key, Token, Expiry);
CREATE TABLE tokens(Token text primary key, Username text, Expiry int);
CREATE TABLE connections(UUID text primary key, Username text, Connection text, Source text, PeerID text, Expiry int);
```
