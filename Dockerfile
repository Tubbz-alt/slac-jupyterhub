FROM centos:7

USER root

RUN  yum install -y epel-release
RUN  yum repolist
RUN  yum -y upgrade

RUN  yum install -y nodejs libcurl-devel mysql-devel gcc net-tools sudo \
      git patch
# Python 3.6: install from SCL
RUN  yum -y install centos-release-scl && \
     yum-config-manager --enable rhel-server-rhscl-7-rpms && \
     yum -y install rh-python36
RUN  source scl_source enable rh-python36 && \
      pip3 install --upgrade pip setuptools
RUN  npm install -g configurable-http-proxy
RUN  source scl_source enable rh-python36 && \
     pip3 install jupyterlab ipykernel pyyaml pycurl==7.43.0.1 python-oauth2 wheel \
      cryptography mysqlclient
RUN  source scl_source enable rh-python36 && \
      pip3 install \
        jupyterhub \
        jupyterhub-kubespawner \
        batchspawner \
        oauthenticator \
        https://github.com/jupyterhub/ldapauthenticator/zipball/master	

RUN  source scl_source enable rh-python36 && \
      jupyter serverextension enable --py \
      jupyterlab --sys-prefix

ENV JUPYTERHUB_BIN=/opt/jupyterhub
      
RUN  mkdir -p ${JUPYTERHUB_BIN}/config
COPY hublauncher.sh hubwrapper.sh ${JUPYTERHUB_BIN}/

COPY local01-scl.sh /etc/profile.d/

# jupyterhub_config.py is stored in a ConfigMap
ENV  LANG=C.UTF-8
RUN  groupadd -g 768 jupyter
RUN  useradd -m -g jupyter -u 768 -c "JupyterHub User" jupyter

CMD [ "/opt/jupyterhub/hublauncher.sh" ]
