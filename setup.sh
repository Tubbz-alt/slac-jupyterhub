#!/bin/bash

set -x


K8S_NAMESPACE="default"
if [ -n "${1}" ]; then
    K8S_NAMESPACE="${1}"
fi

echo "Running for namespace " $K8S_NAMESPACE


kubectl create namespace $K8S_NAMESPACE

kubectl create -n $K8S_NAMESPACE -f kubernetes/service.yaml

###
# RBAC
###
kubectl create -n $K8S_NAMESPACE -f kubernetes/service_account.yaml

sed "s/__NAMESPACE__/$K8S_NAMESPACE/g" kubernetes/role.yaml | kubectl create -f -
sed "s/__NAMESPACE__/$K8S_NAMESPACE/g" kubernetes/rolebinding.yaml | kubectl create -n $K8S_NAMESPACE -f -

###
# secrets
###
kubectl create -n $K8S_NAMESPACE -f kubernetes/secrets.yaml

###
# data for hub
###
HUB_DATA_DIR=/mnt/hub-data
kubectl delete -n $K8S_NAMESPACE pv hub-data
sed "s|__HUB_DATA_DIR__|$HUB_DATA_DIR|g" kubernetes/pv_hub-data.yaml | kubectl create -n $K8S_NAMESPACE -f -
sleep 3
kubectl delete -n $K8S_NAMESPACE pvc hub-data
kubectl create -n $K8S_NAMESPACE -f kubernetes/pvc_hub-data.yaml


###
# setup hub customisations
###
kubectl create -n $K8S_NAMESPACE configmap hub-config \
	--from-file=config/jupyterhub_config.py \
	--from-file=config/jupyterhub_config.d
kubectl create -n $K8S_NAMESPACE -f kubernetes/deployment.yaml

###
# setup prepuller to preget images
###
sed "s/__NAMESPACE__/$K8S_NAMESPACE/g" prepuller/prepuller-serviceaccount.yml | kubectl -n $K8S_NAMESPACE create -f -
sed "s/__NAMESPACE__/$K8S_NAMESPACE/g" prepuller/prepuller-clusterrole.yml | kubectl -n $K8S_NAMESPACE create -f -
sed "s/__NAMESPACE__/$K8S_NAMESPACE/g" prepuller/prepuller-role.yml | kubectl -n $K8S_NAMESPACE create -f -

sed "s/__NAMESPACE__/$K8S_NAMESPACE/g" prepuller/prepuller-clusterrolebinding.yml | kubectl -n $K8S_NAMESPACE create -f -
sed "s/__NAMESPACE__/$K8S_NAMESPACE/g" prepuller/prepuller-rolebinding.yml | kubectl -n $K8S_NAMESPACE create -f -

sed "s/__NAMESPACE__/$K8S_NAMESPACE/g" prepuller/prepuller-cronjob.yml | kubectl -n $K8S_NAMESPACE create -f -


