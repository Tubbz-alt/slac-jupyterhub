# TODO: make into real script

kubectl create namespace ingress-nginx

cd ~/certs
kubectl create -n jupyter secret tls tls-certificate --key jupyter.key --cert jupyter.crt
cat jupytercrt jupyter.key > dhparam.pem
kubectl create -n ingress-nginx secret generic tls-dhparam --from-file=dhparam.pem



# create backend
kubectl create -n ingress-nginx -f kubernetes/ingress-backend.yaml 
kubectl create -n ingress-nginx -f kubernetes/ingress-rbac.yaml
kubectl create -n ingress-nginx -f kubernetes/ingress-controller.yaml

# but need to assign the nodes that this should run on via the nodeSelector for edge-router


kubectl get nodes
kubectl label nodes dhcp-nebula-129-230 role=edge-router

# then the daemonset should populate out
kubectl get ds --all-namespaces

# and 
kubectl get all --all-namespaces
kube-system   po/nginx-ingress-controller-v1-944jn               0/1       Pending        0          38s

###
# add ingress definitino
##
kubectl create -n jupyter -f kubernetes/ingress-hub.yaml

