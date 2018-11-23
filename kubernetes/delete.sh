#!/bin/bash

# set -x

CONFIG_FILE="ENVIRONMENT"
if [ -n "${1}" ]; then
    CONFIG_FILE="${1}"
fi

# import key value pairs
source ./${CONFIG_FILE}

# stolen from https://starkandwayne.com/blog/bashing-your-yaml/
function gen_template() {
    rm -f final.yaml temp.yaml  
    ( echo "cat <<EOF >final.yaml";
      cat $1;
      echo "EOF";
    ) >temp.yaml
    . temp.yaml
    cat final.yaml
    rm -f final.yaml temp.yaml  
}

# create the namespace for this project
kubectl delete namespace ${namespace} -R

kubectl delete pv ${namespace}--generic-user-home ${namespace}--hub-data ${namespace}--local-home ${namespace}--jupyter-home ${namespace}--lsst-data ${namespace}--lsst-home ${namespace}--gpfs ${namespace}--nfs ${namespace}--scratch ${namespace}--tmp
