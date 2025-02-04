# rbac-migration
Tool to migrate users from KubeSaw compliant identities to Red Hat sso identities

Build:

`go build -o wscli` 

Usage:

Call `kscli migrate -h` for usage. Defaults options will target default kubconfig, sso user as the target identity, and output file migrated_rolebindings.yaml.

To run this tool you will first need to login to the member cluster being migrated and Red Hat VPN
