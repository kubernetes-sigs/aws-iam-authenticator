#!/usr/bin/env bash

DOWN=${DOWN:true}

super_echo() {
  echo ""
  echo "**"
  echo "**$1"
  echo "**"
}

super_echo "WARNING: this script is experimental, run at your own risk!"

super_echo "Install kubetest"
if [ ! -d "test-infra" ] ; then
  git clone https://github.com/kubernetes/test-infra.git
fi
pushd test-infra
go install ./kubetest
popd

super_echo "Install hack/local-cluster-up.sh"
if [ ! -d "kubernetes" ] ; then
  git clone https://github.com/kubernetes/kubernetes.git
fi
pushd kubernetes
git checkout release-1.17
hack/install-etcd.sh

super_echo "Init authenticator for the .kubeconfig"
aws-iam-authenticator init -i my-dev-cluster.example.com
cp cert.pem /var/aws-iam-authenticator/cert.pem
cp key.pem /var/aws-iam-authenticator/key.pem
cp aws-iam-authenticator.kubeconfig /etc/kubernetes/aws-iam-authenticator/kubeconfig.yaml

down_and_exit() {
  if [ "$DOWN" == "true" ]; then
    super_echo "Down cluster"
    kubetest --deployment local --down
    sudo pkill -f kubelet
  fi
  exit $!
}

trap down_and_exit SIGINT

super_echo "Up cluster"
sudo pkill -f kubelet
AUTHENTICATION_WEBHOOK_CONFIG_FILE=$PWD/aws-iam-authenticator.kubeconfig kubetest --deployment local --up
if [ $? == 1 ]; then
  super_echo "FAIL!"
  down_and_exit 1
fi

super_echo "Configure cluster"
alias kubectl=$PWD/cluster/kubectl.sh
export KUBECONFIG=$PWD/local.kubeconfig
kubectl config set-cluster local --server=https://localhost:6443 --certificate-authority=/var/run/kubernetes/server-ca.crt

super_echo "Create client certificate authentication 'admin' user"
kubectl config set-credentials admin --client-key=/var/run/kubernetes/client-admin.key --client-certificate=/var/run/kubernetes/client-admin.crt

super_echo "Create aws-iam-authenticator exec authentication 'myself' user"
kubectl config set-credentials myself --exec-command=aws-iam-authenticator --exec-arg=token,-i,my-dev-cluster.example.com --exec-api-version=client.authentication.k8s.io/v1alpha1
kubectl config set-context local --cluster=local --user=myself
kubectl config use-context local

super_echo "Test should be unauthorized when authenticator isn't yet running"
kubectl get po
if [ $? == 0 ]; then
  super_echo "FAIL!"
  down_and_exit 1
fi
super_echo "PASS!"

super_echo "Test should be authorized when authenticator is running and role is in mapRoles"
export ARN=`aws sts get-caller-identity | jq -r .Arn`
sed "s,arn:aws:iam::000000000000:role/KubernetesAdmin,$ARN,g" ../deploy/example.yaml | \
  sed "\,nodeSelector:,d" | \
  sed "\,node-role.kubernetes.io/master: "",d" | \
  kubectl apply -f - --user admin
until kubectl get daemonset -n kube-system aws-iam-authenticator -o jsonpath='{.status.numberReady}' --user admin | grep -q 1;
do
  echo "waiting for daemonset ready..."
  sleep 5
done
echo "daemonset ready"
sleep 5
kubectl get po
if [ $? == 1 ]; then
  super_echo "FAIL!"
  down_and_exit 1
fi
super_echo "PASS!"

down_and_exit 0
