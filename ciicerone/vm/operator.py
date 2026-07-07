"""VM Operator for controlling virtual machines.

This module provides the interface for AI agents to interact with VMs,
including command execution, file transfer, and screenshot capture.
"""

import asyncio
import logging
import time
from typing import Any, Dict, List, Optional, Tuple
from pathlib import Path

from .models import (
    VMConfig,
    VMInfo,
    VMState,
    CommandResult,
    InfrastructureConfig,
    HypervisorType,
)

logger = logging.getLogger(__name__)


class VMOperator:
    """
    Interface for AI agent to control virtual machines.

    Provides capabilities for:
    - VM lifecycle management (create, start, stop, destroy)
    - Command execution (SSH for Linux, WinRM for Windows)
    - File transfer (upload/download)
    - Screenshot capture
    - Snapshot management

    Supports multiple hypervisors:
    - Docker (default, easiest to set up)
    - Proxmox VE
    - VMware vSphere
    - Libvirt/KVM
    - Cloud providers (AWS, Azure, GCP)

    Example:
        config = InfrastructureConfig(hypervisor_type=HypervisorType.DOCKER)
        operator = VMOperator(config)

        # Create attacker VM
        vm = await operator.create_vm(
            VMConfig(name="attacker", template="ubuntu-attacker", is_attacker=True)
        )

        # Execute command
        result = await operator.execute_command(vm.vm_id, "nmap -sV target")
        print(result.stdout)
    """

    def __init__(self, config: Optional[InfrastructureConfig] = None):
        """Initialize VM operator.

        Args:
            config: Infrastructure configuration. Defaults to Docker-based setup.
        """
        self.config = config or InfrastructureConfig()
        self._hypervisor = self._init_hypervisor()
        self._active_vms: Dict[str, VMInfo] = {}
        self._connections: Dict[str, Any] = {}

    def _init_hypervisor(self) -> "BaseHypervisor":
        """Initialize the hypervisor client based on config."""
        hypervisor_map = {
            HypervisorType.DOCKER: DockerHypervisor,
            HypervisorType.PROXMOX: ProxmoxHypervisor,
            HypervisorType.LIBVIRT: LibvirtHypervisor,
        }

        hypervisor_class = hypervisor_map.get(
            self.config.hypervisor_type,
            DockerHypervisor
        )
        return hypervisor_class(self.config)

    async def create_vm(self, vm_config: VMConfig) -> VMInfo:
        """
        Create a new VM from template.

        Args:
            vm_config: Configuration for the new VM

        Returns:
            VMInfo with details of created VM
        """
        logger.info(f"Creating VM: {vm_config.name} from template {vm_config.template}")

        # Create VM through hypervisor
        vm_id = await self._hypervisor.create_vm(vm_config)

        # Wait for VM to be ready
        ip_address = await self._wait_for_vm_ready(vm_id, vm_config)

        vm_info = VMInfo(
            vm_id=vm_id,
            name=vm_config.name,
            state=VMState.RUNNING,
            os_type=vm_config.os_type,
            ip_address=ip_address,
            config=vm_config,
        )

        self._active_vms[vm_id] = vm_info
        logger.info(f"VM created: {vm_id} at {ip_address}")

        return vm_info

    async def execute_command(
        self,
        vm_id: str,
        command: str,
        timeout_seconds: int = 60,
        capture_screenshot: bool = False,
        working_dir: Optional[str] = None,
    ) -> CommandResult:
        """
        Execute a command on the VM.

        Args:
            vm_id: ID of target VM
            command: Command to execute
            timeout_seconds: Command timeout
            capture_screenshot: Whether to capture screen after command
            working_dir: Working directory for command

        Returns:
            CommandResult with output and optional screenshot
        """
        start_time = time.time()

        # Get VM info
        vm_info = self._active_vms.get(vm_id)
        if not vm_info:
            raise ValueError(f"VM not found: {vm_id}")

        # Get or create connection
        conn = await self._get_connection(vm_id, vm_info)

        # Execute command
        try:
            if vm_info.os_type == "windows":
                stdout, stderr, exit_code = await self._execute_winrm(
                    conn, command, timeout_seconds, working_dir
                )
            else:
                stdout, stderr, exit_code = await self._execute_ssh(
                    conn, command, timeout_seconds, working_dir
                )
        except asyncio.TimeoutError:
            return CommandResult(
                command=command,
                stdout="",
                stderr="Command timed out",
                exit_code=-1,
                execution_time_ms=(time.time() - start_time) * 1000,
                vm_id=vm_id,
            )

        execution_time = (time.time() - start_time) * 1000

        # Capture screenshot if requested
        screenshot = None
        if capture_screenshot:
            screenshot = await self.capture_screenshot(vm_id)

        return CommandResult(
            command=command,
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
            execution_time_ms=execution_time,
            screenshot=screenshot,
            vm_id=vm_id,
        )

    async def execute_script(
        self,
        vm_id: str,
        script_content: str,
        script_type: str = "bash",
        args: Optional[List[str]] = None,
    ) -> CommandResult:
        """
        Upload and execute a script on the VM.

        Args:
            vm_id: Target VM ID
            script_content: Script content to execute
            script_type: Type of script (bash, python, powershell)
            args: Arguments to pass to script

        Returns:
            CommandResult with script output
        """
        # Determine script extension and interpreter
        script_map = {
            "bash": (".sh", "bash"),
            "python": (".py", "python3"),
            "powershell": (".ps1", "powershell -ExecutionPolicy Bypass -File"),
            "perl": (".pl", "perl"),
            "ruby": (".rb", "ruby"),
        }

        ext, interpreter = script_map.get(script_type, (".sh", "bash"))

        # Generate unique script path
        script_name = f"ciicerone_script_{int(time.time())}{ext}"
        if script_type == "powershell":
            remote_path = f"C:\\Windows\\Temp\\{script_name}"
        else:
            remote_path = f"/tmp/{script_name}"

        # Upload script
        await self.upload_file(vm_id, script_content.encode(), remote_path)

        # Make executable (Linux/Unix)
        if script_type in ["bash", "python", "perl", "ruby"]:
            await self.execute_command(vm_id, f"chmod +x {remote_path}")

        # Build execution command
        cmd = f"{interpreter} {remote_path}"
        if args:
            cmd += " " + " ".join(args)

        # Execute script
        result = await self.execute_command(vm_id, cmd)

        # Cleanup script file
        if script_type == "powershell":
            await self.execute_command(vm_id, f"Remove-Item -Path '{remote_path}' -Force")
        else:
            await self.execute_command(vm_id, f"rm -f {remote_path}")

        return result

    async def upload_file(
        self,
        vm_id: str,
        content: bytes,
        remote_path: str,
    ) -> bool:
        """
        Upload file to VM.

        Args:
            vm_id: Target VM ID
            content: File content as bytes
            remote_path: Destination path on VM

        Returns:
            True if successful
        """
        vm_info = self._active_vms.get(vm_id)
        if not vm_info:
            raise ValueError(f"VM not found: {vm_id}")

        conn = await self._get_connection(vm_id, vm_info)

        if vm_info.os_type == "windows":
            await self._upload_winrm(conn, content, remote_path)
        else:
            await self._upload_sftp(conn, content, remote_path)

        logger.debug(f"Uploaded file to {vm_id}:{remote_path}")
        return True

    async def download_file(
        self,
        vm_id: str,
        remote_path: str,
    ) -> bytes:
        """
        Download file from VM.

        Args:
            vm_id: Source VM ID
            remote_path: Path to file on VM

        Returns:
            File content as bytes
        """
        vm_info = self._active_vms.get(vm_id)
        if not vm_info:
            raise ValueError(f"VM not found: {vm_id}")

        conn = await self._get_connection(vm_id, vm_info)

        if vm_info.os_type == "windows":
            return await self._download_winrm(conn, remote_path)
        else:
            return await self._download_sftp(conn, remote_path)

    async def capture_screenshot(self, vm_id: str) -> Optional[bytes]:
        """
        Capture screenshot of VM display.

        Args:
            vm_id: VM to screenshot

        Returns:
            Screenshot as PNG bytes, or None if not supported
        """
        return await self._hypervisor.capture_screenshot(vm_id)

    async def snapshot_vm(self, vm_id: str, name: str) -> str:
        """
        Create snapshot of VM state.

        Args:
            vm_id: VM to snapshot
            name: Snapshot name

        Returns:
            Snapshot ID
        """
        snapshot_id = await self._hypervisor.create_snapshot(vm_id, name)

        if vm_id in self._active_vms:
            self._active_vms[vm_id].snapshots.append(snapshot_id)

        logger.info(f"Created snapshot {snapshot_id} for VM {vm_id}")
        return snapshot_id

    async def restore_snapshot(self, vm_id: str, snapshot_id: str) -> bool:
        """
        Restore VM to snapshot state.

        Args:
            vm_id: VM to restore
            snapshot_id: Snapshot to restore to

        Returns:
            True if successful
        """
        # Close existing connection (state will change)
        if vm_id in self._connections:
            await self._close_connection(vm_id)

        success = await self._hypervisor.restore_snapshot(vm_id, snapshot_id)

        # Wait for VM to be ready again
        if success:
            vm_info = self._active_vms.get(vm_id)
            if vm_info and vm_info.config:
                await self._wait_for_vm_ready(vm_id, vm_info.config)

        return success

    async def get_network_info(self, vm_id: str) -> Dict[str, Any]:
        """Get network configuration of VM."""
        vm_info = self._active_vms.get(vm_id)
        if not vm_info:
            raise ValueError(f"VM not found: {vm_id}")

        if vm_info.os_type == "windows":
            result = await self.execute_command(vm_id, "ipconfig /all")
        else:
            result = await self.execute_command(
                vm_id,
                "ip addr show; echo '---ROUTES---'; ip route; echo '---DNS---'; cat /etc/resolv.conf 2>/dev/null || true"
            )

        return {
            "vm_id": vm_id,
            "ip_address": vm_info.ip_address,
            "raw_output": result.stdout,
        }

    async def list_processes(self, vm_id: str) -> List[Dict[str, Any]]:
        """List running processes on VM."""
        vm_info = self._active_vms.get(vm_id)
        if not vm_info:
            raise ValueError(f"VM not found: {vm_id}")

        if vm_info.os_type == "windows":
            result = await self.execute_command(
                vm_id,
                "Get-Process | Select-Object Id, ProcessName, CPU, WorkingSet | ConvertTo-Json"
            )
        else:
            result = await self.execute_command(
                vm_id,
                "ps aux --sort=-%mem | head -50"
            )

        return self._parse_process_list(result.stdout, vm_info.os_type)

    async def stop_vm(self, vm_id: str) -> bool:
        """Stop a running VM."""
        if vm_id in self._connections:
            await self._close_connection(vm_id)

        success = await self._hypervisor.stop_vm(vm_id)

        if success and vm_id in self._active_vms:
            self._active_vms[vm_id].state = VMState.STOPPED

        return success

    async def start_vm(self, vm_id: str) -> bool:
        """Start a stopped VM."""
        success = await self._hypervisor.start_vm(vm_id)

        if success and vm_id in self._active_vms:
            self._active_vms[vm_id].state = VMState.RUNNING
            # Wait for it to be ready
            if self._active_vms[vm_id].config:
                await self._wait_for_vm_ready(vm_id, self._active_vms[vm_id].config)

        return success

    async def destroy_vm(self, vm_id: str) -> bool:
        """Destroy VM and clean up resources."""
        # Close connection
        if vm_id in self._connections:
            await self._close_connection(vm_id)

        # Destroy through hypervisor
        success = await self._hypervisor.destroy_vm(vm_id)

        # Remove from tracking
        self._active_vms.pop(vm_id, None)

        logger.info(f"Destroyed VM: {vm_id}")
        return success

    async def cleanup_all(self) -> None:
        """Destroy all active VMs and clean up."""
        vm_ids = list(self._active_vms.keys())
        for vm_id in vm_ids:
            try:
                await self.destroy_vm(vm_id)
            except Exception as e:
                logger.error(f"Failed to destroy VM {vm_id}: {e}")

        # Close any remaining connections
        for vm_id in list(self._connections.keys()):
            await self._close_connection(vm_id)

    # -------------------------------------------------------------------------
    # Private methods
    # -------------------------------------------------------------------------

    async def _wait_for_vm_ready(
        self,
        vm_id: str,
        config: VMConfig,
        timeout: int = 300
    ) -> Optional[str]:
        """Wait for VM to be accessible via SSH/WinRM."""
        start = time.time()

        while time.time() - start < timeout:
            try:
                # Get IP from hypervisor
                ip_address = await self._hypervisor.get_vm_ip(vm_id)
                if not ip_address:
                    await asyncio.sleep(5)
                    continue

                # Try to connect
                vm_info = VMInfo(
                    vm_id=vm_id,
                    name=config.name,
                    state=VMState.RUNNING,
                    os_type=config.os_type,
                    ip_address=ip_address,
                    config=config,
                )
                self._active_vms[vm_id] = vm_info

                await self._get_connection(vm_id, vm_info)
                return ip_address

            except Exception as e:
                logger.debug(f"VM {vm_id} not ready yet: {e}")
                await asyncio.sleep(5)

        raise TimeoutError(f"VM {vm_id} not ready after {timeout} seconds")

    async def _get_connection(self, vm_id: str, vm_info: VMInfo) -> Any:
        """Get or create connection to VM."""
        if vm_id in self._connections:
            return self._connections[vm_id]

        if not vm_info.ip_address:
            raise ValueError(f"No IP address for VM {vm_id}")

        config = vm_info.config
        if not config:
            raise ValueError(f"No config for VM {vm_id}")

        if vm_info.os_type == "windows":
            conn = await self._create_winrm_connection(vm_info)
        else:
            conn = await self._create_ssh_connection(vm_info)

        self._connections[vm_id] = conn
        return conn

    async def _create_ssh_connection(self, vm_info: VMInfo) -> Any:
        """Create SSH connection to Linux VM."""
        try:
            import asyncssh
        except ImportError:
            raise ImportError("asyncssh required for SSH connections: pip install asyncssh")

        config = vm_info.config

        connect_kwargs = {
            "host": vm_info.ip_address,
            "username": config.ssh_user,
            "known_hosts": None,  # Disable host key checking for lab environment
        }

        if config.ssh_key_path:
            connect_kwargs["client_keys"] = [config.ssh_key_path]
        elif config.ssh_password:
            connect_kwargs["password"] = config.ssh_password

        return await asyncssh.connect(**connect_kwargs)

    async def _create_winrm_connection(self, vm_info: VMInfo) -> Any:
        """Create WinRM connection to Windows VM."""
        try:
            import winrm
        except ImportError:
            raise ImportError("pywinrm required for Windows connections: pip install pywinrm")

        config = vm_info.config

        session = winrm.Session(
            vm_info.ip_address,
            auth=(config.ssh_user, config.ssh_password),
            transport="ntlm",
        )

        return session

    async def _execute_ssh(
        self,
        conn: Any,
        command: str,
        timeout: int,
        working_dir: Optional[str],
    ) -> Tuple[str, str, int]:
        """Execute command via SSH."""
        if working_dir:
            command = f"cd {working_dir} && {command}"

        result = await asyncio.wait_for(
            conn.run(command, check=False),
            timeout=timeout
        )

        return result.stdout, result.stderr, result.returncode

    async def _execute_winrm(
        self,
        conn: Any,
        command: str,
        timeout: int,
        working_dir: Optional[str],
    ) -> Tuple[str, str, int]:
        """Execute command via WinRM."""
        if working_dir:
            command = f"cd {working_dir}; {command}"

        # WinRM is synchronous, run in thread pool
        loop = asyncio.get_event_loop()
        result = await asyncio.wait_for(
            loop.run_in_executor(None, conn.run_ps, command),
            timeout=timeout
        )

        return (
            result.std_out.decode("utf-8", errors="ignore"),
            result.std_err.decode("utf-8", errors="ignore"),
            result.status_code,
        )

    async def _upload_sftp(self, conn: Any, content: bytes, remote_path: str) -> None:
        """Upload file via SFTP."""
        async with conn.start_sftp_client() as sftp:
            async with sftp.open(remote_path, "wb") as f:
                await f.write(content)

    async def _download_sftp(self, conn: Any, remote_path: str) -> bytes:
        """Download file via SFTP."""
        async with conn.start_sftp_client() as sftp:
            async with sftp.open(remote_path, "rb") as f:
                return await f.read()

    async def _upload_winrm(self, conn: Any, content: bytes, remote_path: str) -> None:
        """Upload file via WinRM (base64 encoded)."""
        import base64
        encoded = base64.b64encode(content).decode("ascii")

        # PowerShell command to decode and write file
        ps_cmd = f"""
        $bytes = [Convert]::FromBase64String('{encoded}')
        [IO.File]::WriteAllBytes('{remote_path}', $bytes)
        """

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, conn.run_ps, ps_cmd)

    async def _download_winrm(self, conn: Any, remote_path: str) -> bytes:
        """Download file via WinRM (base64 encoded)."""
        import base64

        ps_cmd = f"[Convert]::ToBase64String([IO.File]::ReadAllBytes('{remote_path}'))"

        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, conn.run_ps, ps_cmd)

        encoded = result.std_out.decode("utf-8").strip()
        return base64.b64decode(encoded)

    async def _close_connection(self, vm_id: str) -> None:
        """Close connection to VM."""
        if vm_id in self._connections:
            conn = self._connections.pop(vm_id)
            if hasattr(conn, "close"):
                try:
                    conn.close()
                except Exception:
                    pass

    def _parse_process_list(self, output: str, os_type: str) -> List[Dict[str, Any]]:
        """Parse process list output."""
        processes = []

        if os_type == "windows":
            try:
                import json
                return json.loads(output)
            except Exception:
                return []
        else:
            # Parse ps aux output
            lines = output.strip().split("\n")[1:]  # Skip header
            for line in lines:
                parts = line.split(None, 10)
                if len(parts) >= 11:
                    processes.append({
                        "user": parts[0],
                        "pid": parts[1],
                        "cpu": parts[2],
                        "mem": parts[3],
                        "command": parts[10],
                    })

        return processes


# =============================================================================
# Hypervisor Implementations
# =============================================================================

class BaseHypervisor:
    """Base class for hypervisor implementations."""

    def __init__(self, config: InfrastructureConfig):
        self.config = config

    async def create_vm(self, vm_config: VMConfig) -> str:
        raise NotImplementedError

    async def start_vm(self, vm_id: str) -> bool:
        raise NotImplementedError

    async def stop_vm(self, vm_id: str) -> bool:
        raise NotImplementedError

    async def destroy_vm(self, vm_id: str) -> bool:
        raise NotImplementedError

    async def get_vm_ip(self, vm_id: str) -> Optional[str]:
        raise NotImplementedError

    async def create_snapshot(self, vm_id: str, name: str) -> str:
        raise NotImplementedError

    async def restore_snapshot(self, vm_id: str, snapshot_id: str) -> bool:
        raise NotImplementedError

    async def capture_screenshot(self, vm_id: str) -> Optional[bytes]:
        return None  # Not all hypervisors support this


class DockerHypervisor(BaseHypervisor):
    """Docker-based hypervisor (easiest to set up)."""

    def __init__(self, config: InfrastructureConfig):
        super().__init__(config)
        self._client = None

    def _get_client(self):
        """Get Docker client."""
        if self._client is None:
            try:
                import docker
                self._client = docker.from_env()
            except ImportError:
                raise ImportError("docker package required: pip install docker")
        return self._client

    async def create_vm(self, vm_config: VMConfig) -> str:
        """Create container as VM."""
        client = self._get_client()

        # Map template names to Docker images
        image_map = {
            "ubuntu-attacker": "ciicerone/ubuntu-attacker:latest",
            "ubuntu-target": "ubuntu:22.04",
            "windows-target": "mcr.microsoft.com/windows/servercore:ltsc2022",
        }

        image = image_map.get(vm_config.template, vm_config.template)

        # Create container
        loop = asyncio.get_event_loop()
        container = await loop.run_in_executor(
            None,
            lambda: client.containers.run(
                image,
                name=vm_config.name,
                detach=True,
                network=self.config.attack_network_name,
                mem_limit=f"{vm_config.memory_gb}g",
                cpu_count=vm_config.cpu_cores,
                environment={
                    "SSH_USER": vm_config.ssh_user,
                    "SSH_PASSWORD": vm_config.ssh_password or "ciicerone",
                },
                # Keep container running
                command="tail -f /dev/null" if vm_config.os_type != "windows" else None,
            )
        )

        return container.id

    async def start_vm(self, vm_id: str) -> bool:
        """Start container."""
        client = self._get_client()
        try:
            container = client.containers.get(vm_id)
            container.start()
            return True
        except Exception as e:
            logger.error(f"Failed to start container {vm_id}: {e}")
            return False

    async def stop_vm(self, vm_id: str) -> bool:
        """Stop container."""
        client = self._get_client()
        try:
            container = client.containers.get(vm_id)
            container.stop(timeout=10)
            return True
        except Exception as e:
            logger.error(f"Failed to stop container {vm_id}: {e}")
            return False

    async def destroy_vm(self, vm_id: str) -> bool:
        """Remove container."""
        client = self._get_client()
        try:
            container = client.containers.get(vm_id)
            container.remove(force=True)
            return True
        except Exception as e:
            logger.error(f"Failed to remove container {vm_id}: {e}")
            return False

    async def get_vm_ip(self, vm_id: str) -> Optional[str]:
        """Get container IP address."""
        client = self._get_client()
        try:
            container = client.containers.get(vm_id)
            container.reload()

            networks = container.attrs.get("NetworkSettings", {}).get("Networks", {})
            for network_name, network_info in networks.items():
                if network_info.get("IPAddress"):
                    return network_info["IPAddress"]

            return None
        except Exception as e:
            logger.error(f"Failed to get IP for container {vm_id}: {e}")
            return None

    async def create_snapshot(self, vm_id: str, name: str) -> str:
        """Create container commit as snapshot."""
        client = self._get_client()
        container = client.containers.get(vm_id)

        loop = asyncio.get_event_loop()
        image = await loop.run_in_executor(
            None,
            lambda: container.commit(repository="ciicerone-snapshot", tag=name)
        )

        return image.id

    async def restore_snapshot(self, vm_id: str, snapshot_id: str) -> bool:
        """Restore not directly supported in Docker, need to recreate."""
        # For Docker, we'd need to stop, remove, and create new container from snapshot
        # This is a simplified implementation
        logger.warning("Docker snapshot restore requires manual recreation")
        return False


class ProxmoxHypervisor(BaseHypervisor):
    """Proxmox VE hypervisor via the Proxmox REST API (proxmoxer).

    Requires ``proxmoxer`` to be installed::

        pip install proxmoxer requests

    Configure via ``InfrastructureConfig``:
        - ``hypervisor_host``: Proxmox host FQDN / IP
        - ``hypervisor_port``: API port (default 8006)
        - ``hypervisor_user``: API user, e.g. ``root@pam``
        - ``hypervisor_password``: Password or API token secret
        - ``api_token``: ``TOKENID=SECRET`` if using API tokens

    VM IDs in Proxmox are integers; this class returns them as strings
    (e.g. ``"101"``) for API consistency.
    """

    _DEFAULT_NODE = "pve"

    def _get_client(self):
        try:
            from proxmoxer import ProxmoxAPI
        except ImportError:
            raise ImportError(
                "proxmoxer is required for Proxmox support: pip install proxmoxer requests"
            )

        kwargs: Dict[str, Any] = {
            "host": self.config.hypervisor_host,
            "port": self.config.hypervisor_port,
            "verify_ssl": False,
        }
        if self.config.api_token:
            # token format: "USER@REALM!TOKENID=SECRET"
            parts = self.config.api_token.split("=", 1)
            if len(parts) == 2:
                kwargs["user"] = parts[0].rsplit("!", 1)[0]
                kwargs["token_name"] = parts[0].rsplit("!", 1)[-1]
                kwargs["token_value"] = parts[1]
        else:
            kwargs["user"] = self.config.hypervisor_user
            kwargs["password"] = self.config.hypervisor_password

        return ProxmoxAPI(**kwargs)

    def _next_vm_id(self, proxmox) -> int:
        """Ask Proxmox for the next available VM ID."""
        return int(proxmox.cluster.nextid.get())

    def _node(self, proxmox) -> str:
        """Return the first node name from the cluster, defaulting to 'pve'."""
        try:
            nodes = proxmox.nodes.get()
            return nodes[0]["node"] if nodes else self._DEFAULT_NODE
        except Exception:
            return self._DEFAULT_NODE

    async def create_vm(self, vm_config: VMConfig) -> str:
        """Clone a VM from a named template in Proxmox.

        The template must exist on the node with a name matching
        ``vm_config.template``. The clone is created with the VM name
        set to ``vm_config.name``.
        """
        loop = asyncio.get_event_loop()

        def _clone():
            proxmox = self._get_client()
            node = self._node(proxmox)

            # Find template VM ID by name
            vms = proxmox.nodes(node).qemu.get()
            template_id = None
            for vm in vms:
                if vm.get("name") == vm_config.template:
                    template_id = vm["vmid"]
                    break
            if template_id is None:
                raise ValueError(
                    f"Proxmox template '{vm_config.template}' not found on node '{node}'"
                )

            new_id = self._next_vm_id(proxmox)
            proxmox.nodes(node).qemu(template_id).clone.post(
                newid=new_id,
                name=vm_config.name,
                full=1,
            )
            logger.info("Proxmox: cloned %s → VM %s (%s)", template_id, new_id, vm_config.name)
            return str(new_id)

        return await loop.run_in_executor(None, _clone)

    async def start_vm(self, vm_id: str) -> bool:
        """Start a Proxmox VM by ID."""
        loop = asyncio.get_event_loop()

        def _start():
            proxmox = self._get_client()
            node = self._node(proxmox)
            try:
                proxmox.nodes(node).qemu(int(vm_id)).status.start.post()
                logger.info("Proxmox: started VM %s", vm_id)
                return True
            except Exception as exc:
                logger.error("Proxmox: failed to start VM %s: %s", vm_id, exc)
                return False

        return await loop.run_in_executor(None, _start)

    async def stop_vm(self, vm_id: str) -> bool:
        """Gracefully stop a Proxmox VM (ACPI shutdown)."""
        loop = asyncio.get_event_loop()

        def _stop():
            proxmox = self._get_client()
            node = self._node(proxmox)
            try:
                proxmox.nodes(node).qemu(int(vm_id)).status.shutdown.post()
                logger.info("Proxmox: shutdown VM %s", vm_id)
                return True
            except Exception as exc:
                logger.error("Proxmox: failed to stop VM %s: %s", vm_id, exc)
                return False

        return await loop.run_in_executor(None, _stop)

    async def destroy_vm(self, vm_id: str) -> bool:
        """Stop and delete a Proxmox VM."""
        loop = asyncio.get_event_loop()

        def _destroy():
            proxmox = self._get_client()
            node = self._node(proxmox)
            try:
                # Force-stop first
                proxmox.nodes(node).qemu(int(vm_id)).status.stop.post()
                import time as _time
                _time.sleep(3)
                proxmox.nodes(node).qemu(int(vm_id)).delete()
                logger.info("Proxmox: destroyed VM %s", vm_id)
                return True
            except Exception as exc:
                logger.error("Proxmox: failed to destroy VM %s: %s", vm_id, exc)
                return False

        return await loop.run_in_executor(None, _destroy)

    async def get_vm_ip(self, vm_id: str) -> Optional[str]:
        """Return the first non-loopback IPv4 address via QEMU guest agent."""
        loop = asyncio.get_event_loop()

        def _get_ip():
            proxmox = self._get_client()
            node = self._node(proxmox)
            try:
                ifaces = proxmox.nodes(node).qemu(int(vm_id)).agent("network-get-interfaces").get()
                for iface in ifaces.get("result", []):
                    if iface.get("name") in ("lo", "loopback"):
                        continue
                    for addr in iface.get("ip-addresses", []):
                        if addr.get("ip-address-type") == "ipv4":
                            ip = addr.get("ip-address", "")
                            if not ip.startswith("127."):
                                return ip
            except Exception as exc:
                logger.warning("Proxmox: could not get IP for VM %s: %s", vm_id, exc)
            return None

        return await loop.run_in_executor(None, _get_ip)

    async def create_snapshot(self, vm_id: str, name: str) -> str:
        """Create a Proxmox VM snapshot."""
        loop = asyncio.get_event_loop()

        def _snap():
            proxmox = self._get_client()
            node = self._node(proxmox)
            proxmox.nodes(node).qemu(int(vm_id)).snapshot.post(
                snapname=name,
                description=f"Ciicerone snapshot: {name}",
            )
            logger.info("Proxmox: snapshot '%s' created for VM %s", name, vm_id)
            return name

        return await loop.run_in_executor(None, _snap)

    async def restore_snapshot(self, vm_id: str, snapshot_id: str) -> bool:
        """Rollback a Proxmox VM to a named snapshot."""
        loop = asyncio.get_event_loop()

        def _restore():
            proxmox = self._get_client()
            node = self._node(proxmox)
            try:
                proxmox.nodes(node).qemu(int(vm_id)).snapshot(snapshot_id).rollback.post()
                logger.info("Proxmox: rolled back VM %s to snapshot '%s'", vm_id, snapshot_id)
                return True
            except Exception as exc:
                logger.error("Proxmox: rollback failed for VM %s: %s", vm_id, exc)
                return False

        return await loop.run_in_executor(None, _restore)


class LibvirtHypervisor(BaseHypervisor):
    """Libvirt/KVM hypervisor via the libvirt-python binding.

    Requires ``libvirt-python`` to be installed::

        pip install libvirt-python

    The connection URI is constructed from ``InfrastructureConfig``:
        - Local QEMU/KVM: set ``hypervisor_host = "localhost"``
          → uses ``qemu:///system``
        - Remote KVM via SSH: set ``hypervisor_host`` to the remote host
          → uses ``qemu+ssh://root@HOST/system``

    VM names (not UUIDs) are used as ``vm_id`` throughout this class.
    """

    def _connect(self):
        """Open a libvirt connection, raising ImportError if not available."""
        try:
            import libvirt  # type: ignore
        except ImportError:
            raise ImportError(
                "libvirt-python is required for KVM support: pip install libvirt-python"
            )

        host = self.config.hypervisor_host
        if host in ("localhost", "127.0.0.1"):
            uri = "qemu:///system"
        else:
            user = self.config.hypervisor_user or "root"
            uri = f"qemu+ssh://{user}@{host}/system"

        conn = libvirt.open(uri)
        if conn is None:
            raise RuntimeError(f"Failed to open libvirt connection to {uri}")
        return conn, libvirt

    async def create_vm(self, vm_config: VMConfig) -> str:
        """Define and start a KVM domain from an XML template.

        A minimal libvirt XML domain is generated from ``vm_config``.
        For production usage, provide a full domain XML template via
        the ``template`` field (resolved from ``/etc/libvirt/ciicerone/``).
        """
        loop = asyncio.get_event_loop()

        def _define():
            conn, libvirt = self._connect()
            try:
                xml = _build_domain_xml(vm_config)
                domain = conn.defineXML(xml)
                domain.create()
                logger.info("Libvirt: defined and started domain '%s'", vm_config.name)
                return vm_config.name
            finally:
                conn.close()

        return await loop.run_in_executor(None, _define)

    async def start_vm(self, vm_id: str) -> bool:
        loop = asyncio.get_event_loop()

        def _start():
            conn, libvirt = self._connect()
            try:
                domain = conn.lookupByName(vm_id)
                domain.create()
                logger.info("Libvirt: started domain '%s'", vm_id)
                return True
            except Exception as exc:
                logger.error("Libvirt: failed to start domain '%s': %s", vm_id, exc)
                return False
            finally:
                conn.close()

        return await loop.run_in_executor(None, _start)

    async def stop_vm(self, vm_id: str) -> bool:
        """Send ACPI shutdown to the KVM domain (graceful)."""
        loop = asyncio.get_event_loop()

        def _stop():
            conn, libvirt = self._connect()
            try:
                domain = conn.lookupByName(vm_id)
                domain.shutdown()
                logger.info("Libvirt: shutdown domain '%s'", vm_id)
                return True
            except Exception as exc:
                logger.error("Libvirt: failed to stop domain '%s': %s", vm_id, exc)
                return False
            finally:
                conn.close()

        return await loop.run_in_executor(None, _stop)

    async def destroy_vm(self, vm_id: str) -> bool:
        """Forcibly stop and undefine a KVM domain (removes disk too)."""
        loop = asyncio.get_event_loop()

        def _destroy():
            conn, libvirt = self._connect()
            try:
                domain = conn.lookupByName(vm_id)
                if domain.isActive():
                    domain.destroy()  # force kill
                domain.undefineFlags(
                    libvirt.VIR_DOMAIN_UNDEFINE_MANAGED_SAVE
                    | libvirt.VIR_DOMAIN_UNDEFINE_SNAPSHOTS_METADATA
                )
                logger.info("Libvirt: destroyed domain '%s'", vm_id)
                return True
            except Exception as exc:
                logger.error("Libvirt: failed to destroy domain '%s': %s", vm_id, exc)
                return False
            finally:
                conn.close()

        return await loop.run_in_executor(None, _destroy)

    async def get_vm_ip(self, vm_id: str) -> Optional[str]:
        """Return the first non-loopback IPv4 via QEMU guest agent."""
        loop = asyncio.get_event_loop()

        def _get_ip():
            conn, libvirt = self._connect()
            try:
                domain = conn.lookupByName(vm_id)
                ifaces = domain.interfaceAddresses(
                    libvirt.VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_AGENT
                )
                for iface_name, iface_data in ifaces.items():
                    if iface_name == "lo":
                        continue
                    for addr in iface_data.get("addrs", []):
                        if addr.get("type") == libvirt.VIR_IP_ADDR_TYPE_IPV4:
                            ip = addr.get("addr", "")
                            if not ip.startswith("127."):
                                return ip
            except Exception as exc:
                logger.warning("Libvirt: could not get IP for '%s': %s", vm_id, exc)
            finally:
                conn.close()
            return None

        return await loop.run_in_executor(None, _get_ip)

    async def create_snapshot(self, vm_id: str, name: str) -> str:
        """Create an internal libvirt snapshot for the KVM domain."""
        loop = asyncio.get_event_loop()

        def _snap():
            conn, libvirt = self._connect()
            try:
                domain = conn.lookupByName(vm_id)
                xml = f"""
                <domainsnapshot>
                  <name>{name}</name>
                  <description>Ciicerone snapshot: {name}</description>
                </domainsnapshot>"""
                domain.snapshotCreateXML(xml, 0)
                logger.info("Libvirt: snapshot '%s' created for domain '%s'", name, vm_id)
                return name
            finally:
                conn.close()

        return await loop.run_in_executor(None, _snap)

    async def restore_snapshot(self, vm_id: str, snapshot_id: str) -> bool:
        """Revert the KVM domain to a named snapshot."""
        loop = asyncio.get_event_loop()

        def _restore():
            conn, libvirt = self._connect()
            try:
                domain = conn.lookupByName(vm_id)
                snap = domain.snapshotLookupByName(snapshot_id)
                domain.revertToSnapshot(snap)
                logger.info("Libvirt: reverted domain '%s' to snapshot '%s'", vm_id, snapshot_id)
                return True
            except Exception as exc:
                logger.error("Libvirt: revert failed for '%s': %s", vm_id, exc)
                return False
            finally:
                conn.close()

        return await loop.run_in_executor(None, _restore)


def _build_domain_xml(vm_config: "VMConfig") -> str:  # noqa: F821  (forward ref)
    """Build a minimal libvirt domain XML string from a VMConfig.

    This generates a KVM/QEMU domain suitable for CI/development.
    For production, replace with Jinja2-rendered templates.
    """
    memory_kb = vm_config.memory_gb * 1024 * 1024
    return f"""
<domain type='kvm'>
  <name>{vm_config.name}</name>
  <memory unit='KiB'>{memory_kb}</memory>
  <currentMemory unit='KiB'>{memory_kb}</currentMemory>
  <vcpu placement='static'>{vm_config.cpu_cores}</vcpu>
  <os>
    <type arch='x86_64' machine='pc-i440fx-2.9'>hvm</type>
    <boot dev='hd'/>
  </os>
  <features>
    <acpi/>
    <apic/>
  </features>
  <cpu mode='host-model' check='partial'/>
  <clock offset='utc'/>
  <devices>
    <emulator>/usr/bin/kvm</emulator>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='/var/lib/libvirt/images/{vm_config.name}.qcow2'/>
      <target dev='vda' bus='virtio'/>
    </disk>
    <interface type='network'>
      <source network='default'/>
      <model type='virtio'/>
    </interface>
    <channel type='unix'>
      <target type='virtio' name='org.qemu.guest_agent.0'/>
    </channel>
    <graphics type='vnc' port='-1' autoport='yes'/>
    <video>
      <model type='vga' vram='16384' heads='1'/>
    </video>
  </devices>
</domain>"""
