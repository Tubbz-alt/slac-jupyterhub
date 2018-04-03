FROM centos:7

USER root

RUN  yum install -y epel-release
RUN  yum repolist
RUN  yum -y upgrade
RUN  yum install -y python34 python-pip python34-pip nodejs python34-devel \
       libcurl-devel gcc net-tools sudo git patch
RUN  pip3 install --upgrade pip setuptools

RUN  npm install -g configurable-http-proxy
RUN  pip3 install jupyterlab ipykernel pyyaml pycurl python-oauth2 wheel \
       cryptography
RUN pip3 install \
     https://github.com/jupyterhub/jupyterhub/zipball/master \
     https://github.com/jupyterhub/kubespawner/zipball/master \
     https://github.com/jupyterhub/oauthenticator/zipball/master \
     https://github.com/jupyterhub/ldapauthenticator/zipball/master

RUN python3 /usr/bin/jupyter serverextension enable --py \
     jupyterlab --sys-prefix
      
RUN  mkdir -p /opt/jupyterhub/config
COPY hublauncher.sh /opt/jupyterhub/

# jupyterhub_config.py is stored in a ConfigMap
ENV  LANG=C.UTF-8
RUN  groupadd -g 768 jupyter
RUN  useradd -m -g jupyter -u 768 -c "JupyterHub User" jupyter
LABEL  description="jupyterhub" \
       name="slaclab/jupyterhub" \
       version="0.4.9"

CMD [ "/opt/jupyterhub/hublauncher.sh" ]
