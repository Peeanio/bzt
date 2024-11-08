# bzt-agent

## USAGE

```
go build
./bzt-agent
```

## Config file
`~/.bzt-agent.yaml`
```
server: "http://127.0.0.1:8080"
token: "bar"
cert: "cert.pem"
serverpeerid: "CN=bzt-server.lan"
agentid: "agent"
```

## Addtional installation
1. Put the ca public cert in `/etc/ipsec.d/cacerts`
2. Put the bzt-agent's cert in `/etc/ipsec.d/certs`
3. Put the bzt-agent's private key in `/etc/ipsec.d/private`
4. Edit `/etc/ipsec.secret` with `: ECDSA private.key`
