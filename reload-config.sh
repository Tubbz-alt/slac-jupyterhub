#!/bin/bash

set -x


K8S_NAMESPACE="default"
if [ -n "${1}" ]; then
    K8S_NAMESPACE="${1}"
fi

#kubectl create -n $K8S_NAMESPACE configmap   hub-config \
#        --from-file=config/jupyterhub_config.py \
#        --from-file=config/node-selectors.yaml \
#        --from-file=config/jupyterhub_config.d  -o yaml --dry-run | kubectl replace -n $K8S_NAMESPACE --validate=false -f -

kubectl delete -n $K8S_NAMESPACE configmap hub-config
kubectl create -n $K8S_NAMESPACE configmap hub-config \
        --from-file=config/jupyterhub_config.py \
        --from-file=config/node-selectors.yaml \
        --from-file=config/jupyterhub_config.d \
        --from-file=config/images.d
