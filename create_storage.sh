

sed "s|__HOME_DIR__|/mnt/generic-users|g" kubernetes/pv_generic-user-home.yaml | kubectl -n jupyter create -f -
sed "s|__HOME_DIR__|/gpfs/slac/lsst/fs1/u/|g" kubernetes/pv_lsst-home.yaml | kubectl -n jupyter create -f -
sed "s|__HOME_DIR__|/home|g" kubernetes/pv_local-home.yaml | kubectl -n jupyter create -f -
