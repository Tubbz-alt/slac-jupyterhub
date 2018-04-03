# Introduction

This is the SLAC JupyterHub repository. It contain the kubernetes based production deployment used at SLAC. Specifically, it makes use of kubernetes node selector to place jupyter images onto different hosts based upon the groups that the user is a member of. It also assumed a distribute file system underneath (in our case it's GPFS) where the home directories and jupyter hub database are kept.

We make use of the lsstsqre examples and jupyterlab images to provide docker based jupyterlab instances for users authenticated against the SLAC LDAP.

## Building

docker build . -t slaclab/jupyterhub

push to dockerhub

docker login
docker push slaclab/jupyterhub:latest


## Kubernetes Installation

Please use kubeadm with weave.


## Pre-reqs

In order to provide a service mesh so that you can use the kubernetes cluster as a load balancer itself (ie any requests going to any node of the kubernetes cluster can be routed/ingress'd into the pods), you will need to patch weave on each and every kubernetes node:

sudo -s

cat > /etc/cni/net.d/00-weave.conflist << EOF
{
    "cniVersion": "0.3.0",
    "name": "mynet",
      "plugins": [
        {
            "name": "weave",
            "type": "weave-net",
            "hairpinMode": true
        },
        {
            "type": "portmap",
            "capabilities": {"portMappings": true},
            "snat": true
        }
    ]
}
EOF

you then need to restart the weave pods on each node for it to take affect:

kubectl -n kube-system get po | grep weave-net | awk '{print $1}' | xargs kubectl -n kube-system delete po


## Installation

Once your kubernetes cluster is up, you should be able to check out this git and run:

setup.sh jupyter
setup-ingress.sh 
create_storage.sh
redeploy.sh

You will also need to create certs for the Ingress endpoint to allow the ingress controller to terminate https.


## TODO

- better documentation
- add more dynamic way of specificying non-lsst images
