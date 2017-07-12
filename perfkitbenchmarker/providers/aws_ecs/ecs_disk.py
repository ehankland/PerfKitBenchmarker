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

"""Class to represent an ECS disk object."""

from perfkitbenchmarker import disk
from perfkitbenchmarker import providers
from perfkitbenchmarker.providers.aws import aws_disk


class EcsDiskSpec(aws_disk.AwsDiskSpec):
  """A DiskSpec object compatible with AWS disks."""

  CLOUD = providers.AWS_ECS


class EcsDisk(disk.BaseDisk):
  """Object representing an AWS disk exposed to an ECS container."""

  CLOUD = providers.AWS_ECS

  def _Create(self):
    pass

  def _Delete(self):
    pass

  def Attach(self, vm):
    pass

  def Detach(self):
    pass
