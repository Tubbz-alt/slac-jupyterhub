"""
Put all the sections together.
"""
import os

# Listen to all interfaces
c.JupyterHub.ip = '0.0.0.0'
# Don't try to cleanup servers on exit - since in general for k8s, we want
# the hub to be able to restart without losing user containers
c.JupyterHub.cleanup_servers = False
# Set Hub IP explicitly
c.JupyterHub.hub_ip = os.environ['HUB_BIND_IP']
# Set Session DB URL if we have one
db_url = os.getenv('SESSION_DB_URL')
if db_url:
    c.JupyterHub.db_url = db_url


# set list of admins
c.Authenticator.admin_users = [ 'ytl', ]
