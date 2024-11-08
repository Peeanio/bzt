# bzt

bzt (Berkeley Zero Trust) is a proof of concept zero trust implementation, utilising IPSEC, IPTABLES, and a CONTROL PLANE to limit authorized proven access to network services. 

## TODO

- server: implement ca signing and distribution of certs
- agent client mode: saml sso to get token

## Usage

1. Create or obtain a CA to sign certificates to use
2. Issue a certificate to the `bzt-server` system to use, and one any system connection over ipsec
3. Setup an ipsec session between the server and the agent, and server and client if enforcing ipsec on the server (not required)
4. Seed the server with tokens 
5. Start the agent
6. Authorize connections from clients to backends via the API
7. Connect from client to destination agent server

### Quickstart

1. Provison a CA
```
openssl req -newkey ed25519:2049 -noenc -keyout ca.key -out ca.crt -days 365 -subj "/CN=bzt.lan"
```
2. Create a server cert, agent cert, client cert
```
openssl req -newkey ed25519:2048 -noenc -keyout server.key -out server.csr -subj "/CN=server.bzt.lan"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -out server.crt -days 365

openssl req -newkey ed25519:2048 -noenc -keyout agent.key -out agent.csr -subj "/CN=agent.bzt.lan"
openssl x509 -req -in agent.csr -CA ca.crt -CAkey ca.key -out agent.crt -days 365

openssl req -newkey ed25519:2048 -noenc -keyout client.key -out client.csr -subj "/CN=client.bzt.lan"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -out client.crt -days 365
```
3. Create the inital ipsec connection for server, agent, and client
* server `/etc/ispec.conf`
```
...
conn toagent
    type transport
    authby pubkey
    left=agent.lan
    right=server.lan
    auto=start
    leftcert="CN=agent.bzt.lan"
    keyexchange=ikev2
    ike=aes256-sha512-mod4096!
    esp=aes256-sha512-mod4096!
    closeaction=restart
    dpdaction=restart
```
* agent `/etc/ipsec.conf`
```
...
conn toserver
    type transport
    authby pubkey
    left=server.lan
    right=agent.lan
    auto=start
    leftcert="CN=server.bzt.lan"
    keyexchange=ikev2
    ike=aes256-sha512-mod4096!
    esp=aes256-sha512-mod4096!
    closeaction=restart
    dpdaction=restart
```
* client `/etc/ipsec.conf`
```
...
conn toserver
    type transport
    authby pubkey
    left=server.lan
    right=client.lan
    auto=start
    leftcert="CN=server.bzt.lan"
    keyexchange=ikev2
    ike=aes256-sha512-mod4096!
    esp=aes256-sha512-mod4096!
    closeaction=restart
    dpdaction=restart
conn toagent
    type transport
    authby pubkey
    left=agent.lan
    right=client.lan
    auto=start
    leftcert="CN=agent.bzt.lan"
    keyexchange=ikev2
    ike=aes256-sha512-mod4096!
    esp=aes256-sha512-mod4096!
    closeaction=restart
    dpdaction=restart
```
4. Create a sqlite database on the server, seed with an inital token for agents and users
```
sqlite3 sqlite.db
CREATE TABLE tokens(Token text primary key, Username text, Expiry int);
CREATE TABLE agents(ID int primary key, Token text, Expiry int);
CREATE TABLE connections(UUID text primary key, Username text, Connection text, Source text, PeerID text, Expiry int);
INSERT INTO tokens values('token', 'user', 1735689600);
INSERT INTO agents values('agent', 'token', 1735689600);
```
5. Start the agent, pointing at the `bzt-server`. The agent requires root privileges to make firewall modifications
```
./bzt-agent "http://server.lan:8080"
```
6. As an agent, ask the control plane to authorize a connection
```
curl -XPOST http://server.lan:8080/client/authorize -d '{"token":"token","endpoint":"tcp://agent.bzt.lan:22","peerid":"CN=client.bzt.lan"}'
```
7. Connect from the client to the agent server
```
ssh agent.bzt.lan
```
