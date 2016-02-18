# Copyright 2015 PerfKitBenchmarker Authors. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Module containing mixin classes for linux virtual machines.

These classes allow installation on both Debian and RHEL based linuxes.
They also handle some intial setup (especially on RHEL based linuxes
since by default sudo commands without a tty don't work) and
can restore the VM to the state it was in before packages were
installed.

To install a package on a VM, just call vm.Install(package_name).
The package name is just the name of the package module (i.e. the
file name minus .py). The framework will take care of all cleanup
for you.
"""

import base64
import ntpath

from perfkitbenchmarker import data
from perfkitbenchmarker import errors
from perfkitbenchmarker import flags
from perfkitbenchmarker import vm_util

flags.DEFINE_string('transport', None,
                    'The name of the transport to use (e.g. ssh).')

REMOTE_KEY_PATH = '.ssh/id_rsa'
RHEL = 'rhel'

SSH_WINDOWS = """
cd /
Invoke-WebRequest https://storage.googleapis.com/freesshd/freeSSHd.exe \
    -OutFile freeSSHd.exe
.\\freeSSHd.exe /VERYSILENT /NOICON /SUPPRESSMSGBOXES | Out-Null
netsh advfirewall set allprofiles state off
net stop freesshdservice
$config = @"
{config}
"@

$pub_key = @"
{pub_key}
"@

$pub_key | Out-File -Encoding ASCII \
    'C:\Program Files (x86)\\freeSSHd\{{user_name}}'
$config | Out-File 'C:\Program Files (x86)\\freeSSHd\FreeSSHDService.ini'
net start freesshdservice
"""

SMB_PORT = 445
WINRM_PORT = 5985
WINRM_SCRIPT = """
Enable-PSRemoting -force
Set-Item wsman:\\localhost\\client\\trustedhosts * -Force
Restart-Service WinRM
netsh advfirewall set allprofiles state off
"""
WINDOWS = 'windows'

_TRANSPORT_REGISTRY = {}


def GetDefaultTransportFromOs(os_type):
  """Returns the default transport for a given os type."""
  if os_type == WINDOWS:
    if vm_util.RunningOnWindows():
      return 'WinRM'
    else:
      return 'windows_ssh'
  else:
    return 'ssh'


def GetTransportClass(name):
  """Gets the transport associated with the name."""
  return _TRANSPORT_REGISTRY.get(name)


class AutoRegisterTransport(type):
  """Metaclass which registers transports."""

  def __init__(cls, name, bases, dct):
    super(AutoRegisterTransport, cls).__init__(name, bases, dct)
    if cls.NAME in _TRANSPORT_REGISTRY:
      raise Exception('BaseTransport subclasses must have a NAME attribute.')
    _TRANSPORT_REGISTRY[cls.NAME] = cls


class BaseTransport(object):

  NAME = None
  __metaclass__ = AutoRegisterTransport

  # Ports that will be opened by benchmark_spec to permit access to the VM
  remote_access_ports = []

  def __init__(self, vm):
    self.vm = vm

  def RemoteCommand(self, command, should_log=False, ignore_failure=False,
                    suppress_warning=False, timeout=None):
    """Runs a command on the VM.

    Args:
      command: A valid command.
      should_log: A boolean indicating whether the command result should be
          logged at the info level. Even if it is false, the results will
          still be logged at the debug level.
      ignore_failure: Ignore any failure if set to true.
      suppress_warning: Suppress the result logging from IssueCommand when the
          return code is non-zero.
      timeout: The time to wait in seconds for the command before exiting.
          None means no timeout.

    Returns:
      A tuple of stdout and stderr from running the command.

    Raises:
      RemoteCommandError: If there was a problem issuing the command.
    """
    raise NotImplementedError()

  def RemoteCopy(self, file_path, remote_path, copy_to):
    """Copies a file to or from the VM.

    Args:
      file_path: Local path to file.
      remote_path: Path of where to copy file on remote host.
      copy_to: True to copy to vm, False to copy from vm.

    Raises:
      RemoteCommandError: If there was a problem copying the file.
    """
    raise NotImplementedError()

  def MoveFile(self, target, source_path, remote_path=''):
    """Copies a file from one VM to a target VM.

    Args:
      target: The target BaseVirtualMachine object.
      source_path: The location of the file on the REMOTE machine.
      remote_path: The destination of the file on the TARGET machine, default
          is the home directory.
    """
    raise NotImplementedError()

  def OnStartup(self):
    """Commands which will be run after initially connecting to the VM."""
    pass

  def GetWindowsScript(self):
    """Returns a script to run on a Windows VM to bootstrap the transport."""
    raise NotImplementedError()


class SshTransport(BaseTransport):

  NAME = 'ssh'
  remote_access_ports = [22]

  @classmethod
  def CreateTransportFromVm(cls, vm):
    """Returns a Transport created from VM attributes."""
    return cls(vm.ip_address, vm.ssh_port, vm.user_name, vm.ssh_private_key)

  def RemoteCommand(self, command, should_log=False, ignore_failure=False,
                    suppress_warning=False, timeout=None, ssh_options=None):
    """Runs a command on the VM."""
    if vm_util.RunningOnWindows():
      # Multi-line commands passed to ssh won't work on Windows unless the
      # newlines are escaped.
      command = command.replace('\n', '\\n')

    user_host = '%s@%s' % (self.vm.user_name, self.vm.ip_address)
    ssh_cmd = ['ssh', '-A', '-p', str(self.vm.ssh_port), user_host]
    ssh_cmd.extend(vm_util.GetSshOptions(self.vm.ssh_private_key))
    if ssh_options:
      ssh_cmd.extend(ssh_options)
    ssh_cmd.append(command)

    stdout, stderr, retcode = vm_util.IssueCommand(
        ssh_cmd, force_info_log=should_log,
        suppress_warning=suppress_warning,
        timeout=timeout)

    if retcode:
      full_cmd = ' '.join(ssh_cmd)
      error_text = ('Got non-zero return code (%s) executing %s\n'
                    'Full command: %s\nSTDOUT: %sSTDERR: %s' %
                    (retcode, command, full_cmd, stdout, stderr))
      if not ignore_failure:
        raise errors.VirtualMachine.RemoteCommandError(error_text)

    return stdout, stderr

  def RemoteCopy(self, file_path, remote_path, copy_to):
    """Copies a file to or from the VM."""
    if vm_util.RunningOnWindows():
      if ':' in file_path:
        # scp doesn't like colons in paths.
        file_path = file_path.split(':', 1)[1]
      # Replace the last instance of '\' with '/' to make scp happy.
      file_path = '/'.join(file_path.rsplit('\\', 1))

    remote_location = '%s@%s:%s' % (
        self.vm.user_name, self.vm.ip_address, remote_path)
    scp_cmd = ['scp', '-P', str(self.vm.ssh_port), '-pr']
    scp_cmd.extend(vm_util.GetSshOptions(self.vm.ssh_private_key))
    if copy_to:
      scp_cmd.extend([file_path, remote_location])
    else:
      scp_cmd.extend([remote_location, file_path])

    stdout, stderr, retcode = vm_util.IssueCommand(scp_cmd, timeout=None)

    if retcode:
      full_cmd = ' '.join(scp_cmd)
      error_text = ('Got non-zero return code (%s) executing %s\n'
                    'STDOUT: %sSTDERR: %s' %
                    (retcode, full_cmd, stdout, stderr))
      raise errors.VirtualMachine.RemoteCommandError(error_text)

  def MoveFile(self, target, source_path, remote_path=''):
    """Copies a file from one VM to a target VM.

    Args:
      target: The target BaseVirtualMachine object.
      source_path: The location of the file on the REMOTE machine.
      remote_path: The destination of the file on the TARGET machine, default
          is the home directory.
    """
    if not self.vm.has_private_key:
      self.RemoteCopy(target.ssh_private_key, REMOTE_KEY_PATH)
      self.vm.has_private_key = True

    # TODO(user): For security we may want to include
    #     -o UserKnownHostsFile=/dev/null in the scp command
    #     however for the moment, this has happy side effects
    #     ie: the key is added to know known_hosts which allows
    #     OpenMPI to operate correctly.
    remote_location = '%s@%s:%s' % (
        target.user_name, target.ip_address, remote_path)
    self.RemoteCommand('scp -P %s -o StrictHostKeyChecking=no -i %s %s %s' %
                       (target.ssh_port, REMOTE_KEY_PATH, source_path,
                        remote_location))

  def OnStartup(self):
    """Commands which will be run after initially connecting to the VM."""
    if self.vm.OS_TYPE == RHEL:
      options = ['-t', '-t']
      self.RemoteCommand('echo \'Defaults:%s !requiretty\' | '
                         'sudo tee /etc/sudoers.d/pkb' % self.vm.user_name,
                         ssh_options=options)


class WindowsSshTransport(SshTransport):

  NAME = 'windows_ssh'

  def RemoteCommand(self, command, should_log=False, ignore_failure=False,
                    suppress_warning=False, timeout=None):
    """Runs a command on the VM."""
    command = 'powershell %s' % command
    return super(WindowsSshTransport, self).RemoteCommand(
        command, should_log, ignore_failure, suppress_warning, timeout)

  def MoveFile(self, target, source_path, remote_path=''):
    """Copies a file from one VM to a target VM."""
    raise NotImplementedError()

  def GetWindowsScript(self):
    """Returns the Windows startup script to enable this transport."""
    with open(data.ResourcePath('freesshdservice.ini')) as f:
      config = f.read().strip()
    with open(self.vm.ssh_public_key) as f:
      public_key = f.read().rstrip('\n')

    script = SSH_WINDOWS.format(pub_key=public_key, config=config)
    script = script.format(user_name=self.vm.user_name)
    encoded_script = base64.b64encode(script.encode('utf-16le'))

    return 'powershell -encodedCommand %s' % encoded_script


class WinrmTransport(BaseTransport):

  NAME = 'WinRM'
  remote_access_ports = [WINRM_PORT, SMB_PORT]

  def RemoteCommand(self, command, should_log=False, ignore_failure=False,
                    suppress_warning=False, timeout=None):
    """Runs a command on the VM.

    Args:
      command: A valid bash command.
      should_log: A boolean indicating whether the command result should be
          logged at the info level. Even if it is false, the results will
          still be logged at the debug level.
      ignore_failure: Ignore any failure if set to true.
      suppress_warning: Suppress the result logging from IssueCommand when the
          return code is non-zero.

    Returns:
      A tuple of stdout and stderr from running the command.

    Raises:
      RemoteCommandError: If there was a problem issuing the command.
    """
    set_error_pref = '$ErrorActionPreference="Stop"'

    password = self.vm.password.replace("'", "''")
    create_cred = (
        '$pw = convertto-securestring -AsPlainText -Force \'%s\';'
        '$cred = new-object -typename System.Management.Automation'
        '.PSCredential -argumentlist %s,$pw' % (password, self.vm.user_name))

    create_session = (
        '$session = New-PSSession -Credential $cred -Port %s -ComputerName %s' %
        (self.vm.winrm_port, self.vm.ip_address))

    invoke_command = (
        'Invoke-Command -Session $session -ScriptBlock { %s };'
        'exit Invoke-Command -Session $session -ScriptBlock '
        '{ $LastExitCode }' % command)

    cmd = ';'.join([set_error_pref, create_cred,
                    create_session, invoke_command])

    stdout, stderr, retcode = vm_util.IssueCommand(
        ['powershell', '-Command', cmd], timeout=timeout,
        suppress_warning=suppress_warning, force_info_log=should_log)

    if retcode and not ignore_failure:
      error_text = ('Got non-zero return code (%s) executing %s\n'
                    'Full command: %s\nSTDOUT: %sSTDERR: %s' %
                    (retcode, command, cmd, stdout, stderr))
      raise errors.VirtualMachine.RemoteCommandError(error_text)

    return stdout, stderr

  def RemoteCopy(self, local_path, remote_path='', copy_to=True):
    """Copies a file to or from the VM.

    Args:
      local_path: Local path to file.
      remote_path: Optional path of where to copy file on remote host.
      copy_to: True to copy to vm, False to copy from vm.

    Raises:
      RemoteCommandError: If there was a problem copying the file.
    """
    drive, remote_path = ntpath.splitdrive(remote_path)
    drive = (drive or self.vm.system_drive).rstrip(':')

    set_error_pref = '$ErrorActionPreference="Stop"'

    password = self.vm.password.replace("'", "''")
    create_cred = (
        '$pw = convertto-securestring -AsPlainText -Force \'%s\';'
        '$cred = new-object -typename System.Management.Automation'
        '.PSCredential -argumentlist %s,$pw' % (password, self.vm.user_name))

    psdrive_name = self.vm.name
    root = '\\\\%s\\%s$' % (self.vm.ip_address, drive)
    create_psdrive = (
        'New-PSDrive -Name %s -PSProvider filesystem -Root '
        '%s -Credential $cred' % (psdrive_name, root))

    remote_path = '%s:%s' % (psdrive_name, remote_path)
    if copy_to:
      from_path, to_path = local_path, remote_path
    else:
      from_path, to_path = remote_path, local_path

    copy_item = 'Copy-Item -Path %s -Destination %s' % (from_path, to_path)

    delete_connection = 'net use %s /delete' % root

    cmd = ';'.join([set_error_pref, create_cred, create_psdrive,
                    copy_item, delete_connection])

    stdout, stderr, retcode = vm_util.IssueCommand(
        ['powershell', '-Command', cmd], timeout=None)

    if retcode:
      error_text = ('Got non-zero return code (%s) executing %s\n'
                    'STDOUT: %sSTDERR: %s' %
                    (retcode, cmd, stdout, stderr))
      raise errors.VirtualMachine.RemoteCommandError(error_text)

  def GetWindowsScript(self):
    """Returns the Windows startup script to enable this transport."""
    encoded_script = base64.b64encode(WINRM_SCRIPT.encode('utf-16le'))

    return 'powershell -encodedCommand %s' % encoded_script
