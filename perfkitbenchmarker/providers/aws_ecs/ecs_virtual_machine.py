# Copyright 2017 PerfKitBenchmarker Authors. All rights reserved.
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

"""Class to represent an ECS Virtual Machine object.

All VM specifics are self-contained and the class provides methods to
operate on the VM: boot, shutdown, etc.
"""

import json
import threading

from perfkitbenchmarker import context
from perfkitbenchmarker import flags
from perfkitbenchmarker import linux_virtual_machine
from perfkitbenchmarker import regex_util
from perfkitbenchmarker import virtual_machine
from perfkitbenchmarker import vm_util
from perfkitbenchmarker import providers
from perfkitbenchmarker.providers.aws import aws_ecs
from perfkitbenchmarker.providers.aws_ecs import ecs_disk

FLAGS = flags.FLAGS
_CONTAINER_DEFS = """
[
    {
        "memoryReservation": 500,
        "environment": [],
        "name": "ssh",
        "mountPoints": [
            {
                "sourceVolume": "key",
                "readOnly": false,
                "containerPath": "/root/.ssh"
            },
            {
                "sourceVolume": "sshd_config",
                "containerPath": "/etc/ssh/sshd_config"
            },
            {
                "sourceVolume": "dev",
                "containerPath": "/hostdev/"
            }
        ],
        "image": "ubuntu-upstart",
        "cpu": 0,
        "portMappings": [
            {
                "protocol": "tcp",
                "containerPort": 22,
                "hostPort": 30000
            }
        ],
        "command": [],
        "privileged": true,
        "essential": true,
        "volumesFrom": []
    }
]
"""
_VOLUMES = """
[
    {
        "host": {
            "sourcePath": "/home/ec2-user/.ssh"
        },
        "name": "key"
    },
    {
        "host": {
            "sourcePath": "/tmp/ssh/sshd_config"
        },
        "name": "sshd_config"
    },
    {
        "host": {
            "sourcePath": "/dev/"
        },
        "name": "dev"
    }
]
"""


class EcsVirtualMachine(virtual_machine.BaseVirtualMachine):
  """Object representing an AWS Virtual Machine."""

  CLOUD = providers.AWS_ECS
  _task_def_lock = threading.Lock()

  def __init__(self, vm_spec):
    """Initialize a AWS virtual machine.

    Args:
      vm_spec: virtual_machine.BaseVirtualMachineSpec object of the vm.
    """
    super(EcsVirtualMachine, self).__init__(vm_spec)
    self.arn = None
    self.region = 'us-east-1'
    self.task_definition = aws_ecs.EcsTaskDefinition(
        'pkb', _CONTAINER_DEFS, self.region, _VOLUMES)
    self.user_name = 'root'
    benchmark_spec = context.GetThreadBenchmarkSpec()
    self.cluster = benchmark_spec.container_cluster
    self.host_vm = None

  def _CreateDependencies(self):
    """Creates the task def if it doesn't exist."""
    if not self.task_definition._Exists():
      with self._task_def_lock:
        if not self.task_definition._Exists():
          self.task_definition.Create()

  def _PostCreate(self):
    """Get the instance's data and tag it."""
    describe_cmd = [
        'aws',
        'ecs',
        'describe-tasks',
        '--cluster=%s' % self.cluster.name,
        '--region=%s' % self.region,
        '--tasks=%s' % self.arn]
    stdout, _ = vm_util.IssueRetryableCommand(describe_cmd)
    response = json.loads(stdout)
    task = response['tasks'][0]
    container_instance_arn = task['containerInstanceArn']
    self.ssh_port = 30000
    cmd = [
        'aws',
        'ecs',
        'describe-container-instances',
        '--cluster=%s' % self.cluster.name,
        '--container-instances=%s' % container_instance_arn
    ]
    stdout, _ = vm_util.IssueRetryableCommand(cmd)
    response = json.loads(stdout)
    instance_id = response['containerInstances'][0]['ec2InstanceId']
    self.host_vm = next(vm for vm in self.cluster.vms if vm.id == instance_id)
    self.ip_address = self.host_vm.ip_address

  def PrepareVMEnvironment(self):
    """Gets the internal ip for the container."""
    super(EcsVirtualMachine, self).PrepareVMEnvironment()
    stdout, _ = self.RemoteCommand(
        'ifconfig | grep -A 2 ethwe | grep "inet addr"')
    self.internal_ip = regex_util.ExtractGroup('inet addr:(\S*)', stdout)

  @vm_util.Retry()
  def _Create(self):
    """Create a VM instance."""
    create_cmd = [
        'aws',
        'ecs',
        'run-task',
        '--cluster=%s' % self.cluster.name,
        '--region=%s' % self.region,
        '--task-definition=%s' % self.task_definition.family,
        '--count=1',
        '--placement-constraints=type=distinctInstance']
    stdout, _, _ = vm_util.IssueCommand(create_cmd)
    response = json.loads(stdout)
    task = response['tasks'][0]
    self.arn = task['taskArn']

  def _Delete(self):
    """Delete a VM instance."""
    if self.arn:
      delete_cmd = [
          'aws',
          'ecs',
          'stop-task',
          '--cluster=%s' % self.cluster.name,
          '--region=%s' % self.region,
          '--task=%s' % self.arn]
      vm_util.IssueCommand(delete_cmd)

  def CreateScratchDisk(self, disk_spec):
    """Create a VM's scratch disk.

    Args:
      disk_spec: virtual_machine.BaseDiskSpec object of the disk.
    """
    self.host_vm.CreateScratchDisk(disk_spec)
    scratch_disk = ecs_disk.EcsDisk(disk_spec)
    scratch_disk.device_path = self.host_vm.scratch_disks[-1].GetDevicePath()
    if disk_spec.mount_point:
      self.host_vm.RemoteCommand('sudo umount %s' % disk_spec.mount_point)
      self.MountDisk(scratch_disk.GetDevicePath(), scratch_disk.mount_point)
    self.scratch_disks.append(scratch_disk)

  def AddMetadata(self, **kwargs):
    """Adds metadata to the VM."""
    pass


class DebianBasedAwsVirtualMachine(EcsVirtualMachine,
                                   linux_virtual_machine.DebianMixin):
  pass
