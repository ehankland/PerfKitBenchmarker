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
"""Module containing class for AWS's EC2 Container Service."""

import json

from perfkitbenchmarker import container_service
from perfkitbenchmarker import providers
from perfkitbenchmarker import resource
from perfkitbenchmarker import vm_util
from perfkitbenchmarker.providers.aws import aws_virtual_machine
from perfkitbenchmarker.providers.aws import util

ECS_SSH_PORT = 30000


class EcsTaskDefinition(resource.BaseResource):
  """Class representing an ECS task definition."""

  def __init__(self, family, container_definitions, region,
               volumes=None, placement_constraints=None):
    super(EcsTaskDefinition, self).__init__()
    self.family = family
    self.region = region
    self.arn = None
    self.container_definitions = container_definitions
    self.volumes = volumes
    self.placement_constraints = placement_constraints

  def _Create(self):
    """Registers the task definition."""
    register_cmd = util.AWS_PREFIX + [
        '--region=%s' % self.region,
        'ecs', 'register-task-definition',
        '--family=%s' % self.family,
        '--container-definitions=%s' % self.container_definitions,
    ]
    if self.volumes:
      register_cmd.append('--volumes=%s' % self.volumes)
    if self.placement_constraints:
      register_cmd.append(
          '--placement-constraints=%s' % self.placement_constraints)
    vm_util.IssueCommand(register_cmd)

  def _Exists(self):
    """Returns True if the task definition exists."""
    describe_cmd = util.AWS_PREFIX + [
        '--region=%s' % self.region,
        'ecs',
        'describe-task-definition',
        '--task-definition=%s' % self.family,
    ]
    stdout, _, retcode = vm_util.IssueCommand(describe_cmd)
    if retcode:
      return False
    response = json.loads(stdout)
    self.arn = response['taskDefinition']['taskDefinitionArn']
    status = response['taskDefinition']['status']
    if status == 'ACTIVE':
      return True
    else:
      return False

  def _Delete(self):
    """Deregisters the task definition."""
    deregister_cmd = util.AWS_PREFIX + [
        '--region=%s' % self.region,
        'ecs', 'deregister-task-definition',
        '--task-definition=%s' % self.arn,
    ]
    vm_util.IssueCommand(deregister_cmd)


class EcsCluster(container_service.BaseContainerCluster):
  """Class representing an ECS cluster."""

  CLOUD = providers.AWS

  def __init__(self, spec):
    super(EcsCluster, self).__init__(spec)
    self.region = util.GetRegionFromZone(self.zone)
    spec.vm_spec.image = aws_virtual_machine.GetImage(
        spec.vm_spec.machine_type, self.region,
        'gp2', 'amzn-ami-*.g-amazon-ecs-optimized')
    self.vms = [aws_virtual_machine.RhelBasedAwsVirtualMachine(spec.vm_spec)
                for _ in xrange(spec.vm_count)]
    for vm in self.vms:
      vm.remote_access_ports.append(ECS_SSH_PORT)
      vm.iam_profile_name = 'ecsInstanceRole'
      vm.src_dest_check = False

  def PrepareVms(self):
    """Modifies ECS config and installs container networking software."""
    def _PrepareVm(container_instance):
      container_instance.RemoteCommand('mkdir /tmp/ssh/')
      container_instance.RemoteCommand(
          'echo "StrictModes no" > /tmp/ssh/sshd_config')
      container_instance.RemoteCommand(
          'sudo curl -L git.io/weave -o /usr/local/bin/weave')
      container_instance.RemoteCommand('sudo chmod +x /usr/local/bin/weave')
      container_instance.RemoteCommand('weave launch --awsvpc %s' % ' '.join(
          [vm.internal_ip for vm in self.vms if vm != container_instance]))
      ecs_config = ('ECS_CLUSTER=%s\n'
                    'DOCKER_HOST=unix:///var/run/weave/weave.sock') % self.name
      container_instance.RemoteCommand(
          'echo "%s" | sudo tee /etc/ecs/ecs.config' % ecs_config)
      container_instance.RemoteCommand(
          'sudo stop ecs && sudo rm /var/lib/ecs/data/* && sudo start ecs')
    vm_util.RunThreaded(_PrepareVm, self.vms)

  def _Create(self):
    """Create the cluster."""
    create_cmd = util.AWS_PREFIX + [
        '--region=%s' % self.region,
        'ecs',
        'create-cluster',
        '--cluster-name=%s' % self.name,
    ]
    vm_util.IssueCommand(create_cmd)

  def _Delete(self):
    """Delete the cluster."""
    delete_cmd = util.AWS_PREFIX + [
        '--region=%s' % self.region,
        'ecs',
        'delete-cluster',
        '--cluster=%s' % self.name,
    ]
    vm_util.IssueCommand(delete_cmd)

  def _Exists(self):
    """Returns True if the cluster exists."""
    describe_cmd = util.AWS_PREFIX + [
        '--region=%s' % self.region,
        'ecs',
        'describe-clusters',
        '--cluster=%s' % self.name,
    ]
    stdout, _, _ = vm_util.IssueCommand(describe_cmd)
    response = json.loads(stdout)
    clusters = response['clusters']
    if not clusters:
      return False
    assert len(clusters) == 1, 'Too many clusters'
    status = clusters[0]['status']
    if status == 'ACTIVE':
      return True
    return False
