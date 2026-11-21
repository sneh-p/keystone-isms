import { useState, type ReactNode } from "react";
import { Download } from "lucide-react";
import { fetchBytes } from "@/lib/api";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { Tabs } from "@/components/ui/tabs";
import { CodeBlock } from "@/components/CopyButton";

/** Ready-made ways to install the agents on many hosts at once, filled in with this Keystone's address. The enrolment
 *  key is placed where each tool keeps secrets (an Ansible Vault variable, a Jamf parameter, an RMM secure field). */
export function AgentRollout({ server, enrolmentKey }: { server: string; enrolmentKey: string }) {
  return (
    <Card>
      <CardHeader title="Install on many hosts" description="Deploy the same agents with the tools you already use. Each one installs once and leaves hosts that already have the agent alone. Limit the enrolment key (above) to the size of the rollout, and replace it when you're done." />
      <CardBody>
        <Tabs tabs={[
          { value: "gpo", label: "Group Policy", content: <GroupPolicy server={server} /> },
          { value: "intune", label: "Intune", content: <Intune server={server} /> },
          { value: "rmm", label: "RMM tools", content: <Rmm server={server} /> },
          { value: "mac", label: "Jamf and other Mac MDMs", content: <MacMdm server={server} enrolmentKey={enrolmentKey} /> },
          { value: "ansible", label: "Ansible (Linux)", content: <Ansible server={server} /> },
        ]} defaultValue="gpo" />
      </CardBody>
    </Card>
  );
}

function Steps({ children }: { children: ReactNode }) {
  return <ol className="list-decimal space-y-3 pl-5 text-sm">{children}</ol>;
}

function GroupPolicy({ server }: { server: string }) {
  const script = `# install.ps1: installs the Keystone agent once; later startups do nothing.
$key = Get-Content -Path "$PSScriptRoot\\enrolment-key.txt" -Raw
if (-not (Get-ScheduledTask -TaskName 'Keystone Agent' -ErrorAction SilentlyContinue)) {
    & "$PSScriptRoot\\keystone-agent.ps1" -Install -Server "${server}" -EnrolmentKey $key.Trim()
}`;
  return (
    <Steps>
      <li>Create a share only Domain Computers can read, for example <code className="font-mono">\\corp.example\NETLOGON\Keystone</code>, and put <code className="font-mono">keystone-agent.ps1</code> in it with this <code className="font-mono">install.ps1</code> and a file <code className="font-mono">enrolment-key.txt</code> holding the key:
        <div className="mt-2"><CodeBlock code={script} label="install.ps1" /></div></li>
      <li>In a GPO linked to the computers: Computer Configuration → Policies → Windows Settings → Scripts → Startup → PowerShell Scripts → add <code className="font-mono">install.ps1</code>. Computers install the agent at their next restart.</li>
      <li>When the rollout is done, delete <code className="font-mono">enrolment-key.txt</code> and create a new key here: installed agents keep working with their own tokens.</li>
    </Steps>
  );
}

function Intune({ server }: { server: string }) {
  const install = `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\\keystone-agent.ps1 -Install -Server "${server}" -EnrolmentKey "<enrolment key>"`;
  return (
    <Steps>
      <li>Wrap the script as a Win32 app: <code className="font-mono">IntuneWinAppUtil.exe -c .\keystone -s keystone-agent.ps1 -o .\out</code> (the folder holds only <code className="font-mono">keystone-agent.ps1</code>).</li>
      <li>Apps → Windows → Add → Windows app (Win32), upload the <code className="font-mono">.intunewin</code> file. Install behaviour: System. Install command:
        <div className="mt-2"><CodeBlock code={install} label="Intune install command" /></div>
        Uninstall command: <code className="font-mono">powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%ProgramFiles%\Keystone Agent\keystone-agent.ps1" -Uninstall</code></li>
      <li>Detection rule: File, path <code className="font-mono">%ProgramFiles%\Keystone Agent</code>, file <code className="font-mono">keystone-agent.ps1</code>, exists. Assign to a device group.</li>
      <li>Intune shows the install command to its administrators: limit the key's uses or lifetime, and replace it after the rollout.</li>
    </Steps>
  );
}

function Rmm({ server }: { server: string }) {
  const cmd = `# Run as SYSTEM, with keystone-agent.ps1 attached to the script. KEYSTONE_KEY comes from a secure or custom field.
if (-not (Get-ScheduledTask -TaskName 'Keystone Agent' -ErrorAction SilentlyContinue)) {
    & "$PSScriptRoot\\keystone-agent.ps1" -Install -Server "${server}" -EnrolmentKey $env:KEYSTONE_KEY
}`;
  return (
    <Steps>
      <li>In NinjaOne, Datto RMM, N-central or ConnectWise Automate, create a PowerShell script that runs as SYSTEM, attach <code className="font-mono">keystone-agent.ps1</code>, and keep the enrolment key in the tool's secure variable (shown here as <code className="font-mono">KEYSTONE_KEY</code>):
        <div className="mt-2"><CodeBlock code={cmd} label="RMM script" /></div></li>
      <li>Run it on a test device first, then on a device group or as a scheduled job. Devices that already have the agent are left alone.</li>
    </Steps>
  );
}

function MacMdm({ server, enrolmentKey }: { server: string; enrolmentKey: string }) {
  const [busy, setBusy] = useState<string | null>(null);
  const build = async (kind: "jamf" | "embedded") => {
    setBusy(kind);
    try {
      const agent = new TextDecoder().decode(await fetchBytes("/config/agent/download/macos"));
      const head = kind === "jamf"
        ? `#!/bin/sh
# Jamf Pro: add this as a Script, with Parameter 4 labelled "Keystone address" and Parameter 5 "Enrolment key".
# In the policy, set them to ${server} and the key. Hosts that already have the agent are left alone.
SERVER="$4"; KEY="$5"`
        : `#!/bin/sh
# For Kandji (Custom Script), Mosyle, Addigy and other MDMs: runs as root. The address and key are inside this file:
# limit the key's uses or lifetime in Keystone, and replace it after the rollout.
SERVER="${server}"; KEY="${enrolmentKey}"`;
      const body = `${head}
[ -s /etc/keystone-agent/token ] && exit 0
TMP=$(mktemp -d) || exit 1
cat >"$TMP/keystone-agent.sh" <<'KEYSTONE_AGENT_SCRIPT'
${agent.replace(/\n$/, "")}
KEYSTONE_AGENT_SCRIPT
KEYSTONE_ENROLMENT_KEY="$KEY" /bin/sh "$TMP/keystone-agent.sh" install --server "$SERVER"
status=$?
rm -rf "$TMP"
exit $status
`;
      const url = URL.createObjectURL(new Blob([body], { type: "text/x-shellscript" }));
      const a = document.createElement("a");
      a.href = url;
      a.download = kind === "jamf" ? "keystone-agent-jamf.sh" : "keystone-agent-mdm.sh";
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 10_000);
    } catch {
      toast.error("The macOS agent couldn't be downloaded.");
    } finally {
      setBusy(null);
    }
  };
  return (
    <Steps>
      <li><span className="font-medium">Jamf Pro:</span> download the script below (the macOS agent with a small wrapper), add it under Settings → Scripts, and label Parameter 4 “Keystone address” and Parameter 5 “Enrolment key”. Create a policy for the Macs that runs it once per computer, with those two values.
        <div className="mt-2"><Button size="sm" variant="outline" loading={busy === "jamf"} onClick={() => build("jamf")}><Download /> Jamf script</Button></div></li>
      <li><span className="font-medium">Kandji and other MDMs</span> without script parameters: this version has the address and the current key inside it. Add it as a custom script that runs once as root.
        <div className="mt-2"><Button size="sm" variant="outline" loading={busy === "embedded"} onClick={() => build("embedded")}><Download /> Script with address and key</Button></div></li>
      <li>Some settings need Full Disk Access: give the agent (<code className="font-mono">/bin/sh</code> running <code className="font-mono">/usr/local/lib/keystone-agent/keystone-agent.sh</code>) a privacy preferences profile, or those settings show as unknown.</li>
    </Steps>
  );
}

function Ansible({ server }: { server: string }) {
  const playbook = `# keystone-agent.yml: ansible-playbook -i inventory keystone-agent.yml
# Keep the key in Ansible Vault: ansible-vault encrypt_string '<enrolment key>' --name keystone_enrolment_key
- hosts: linux_servers
  become: true
  vars:
    keystone_server: "${server}"
  tasks:
    - name: Copy the Keystone agent
      ansible.builtin.copy:
        src: keystone-agent.sh
        dest: /root/keystone-agent.sh
        mode: "0700"
    - name: Install the agent (once)
      ansible.builtin.command:
        cmd: sh /root/keystone-agent.sh install --server "{{ keystone_server }}"
        creates: /etc/keystone-agent/token
      environment:
        KEYSTONE_ENROLMENT_KEY: "{{ keystone_enrolment_key }}"
      no_log: true
    - name: Remove the installer copy
      ansible.builtin.file:
        path: /root/keystone-agent.sh
        state: absent`;
  return (
    <Steps>
      <li>Put <code className="font-mono">keystone-agent.sh</code> next to this playbook, encrypt the enrolment key with Ansible Vault, and run it against your Linux hosts:
        <div className="mt-2"><CodeBlock code={playbook} label="Ansible playbook" /></div></li>
      <li>Add <code className="font-mono">--tags</code>, <code className="font-mono">--no-software</code> or <code className="font-mono">--pin</code> to the install line if you use them. Hosts that already have the agent are skipped.</li>
    </Steps>
  );
}
