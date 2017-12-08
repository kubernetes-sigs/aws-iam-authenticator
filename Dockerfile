# Copyright 2017 by the contributors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

FROM alpine:3.7

ENV NONPRIV_USER="nobody"

ADD heptio-authenticator-aws /
RUN chown $NONPRIV_USER:$NONPRIV_USER /heptio-authenticator-aws
RUN mkdir /var/heptio-authenticator-aws && chown -R $NONPRIV_USER:$NONPRIV_USER /var/heptio-authenticator-aws
RUN mkdir /etc/heptio-authenticator-aws && chown -R $NONPRIV_USER:$NONPRIV_USER /etc/heptio-authenticator-aws
RUN mkdir -p /etc/kubernetes/heptio-authenticator-aws && chown -R $NONPRIV_USER:$NONPRIV_USER /etc/kubernetes/heptio-authenticator-aws

USER $NONPRIV_USER

ENTRYPOINT ["/heptio-authenticator-aws"]
