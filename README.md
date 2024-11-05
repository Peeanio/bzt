# bzt

bzt (Berkeley Zero Trust) is a proof of concept zero trust implementation, utilising IPSEC, IPTABLES, and a CONTROL PLANE to limit authorized proven access to network services. 

## TODO

- all: use viper for configuration
- server: implement ca signing and distribution of certs
- rewrite connection tables + api to accomodate cert auth
- agnet: rule setup
- agent: goroutine expire rules
- client: whole tool
