"""
This authenticator uses LDAP to make authentication
and authorization decisions.
"""

import ldap3
from ldap3.utils.conv import escape_filter_chars
import ldapauthenticator
from jupyterhub.auth import Authenticator

from traitlets import Unicode, Int, Bool, List, Union

import os
import json
#import oauthenticator
#from oauthenticator.common import next_page_from_links
from tornado import gen
import re


class SLACAuth(ldapauthenticator.LDAPAuthenticator):
    """ Authenticator for SLAC to use LSST kubespaner
    """
    enable_auth_state = False
    _state = {}

    group_search_base = Unicode(
        config=True,
        default=None,
        allow_none=True,
        help="""
        Base for looking up user group associations. Use with group_search_filter.
        ```
        """
    )
    
    group_search_filter = Unicode(
        config=True,
        default_value="(&(objectclass=posixGroup)(memberUid={username}))",
        allow_none=True,
        help="""
        How to query LDAP for group membership lookup, if group_search_base is used.
        """
    )


    @gen.coroutine
    def pre_spawn_start(self, user, spawner):

        # First pulls can be really slow for the LSST stack containers,
        #  so let's give it a big timeout
        spawner.http_timeout = 60 * 15
        spawner.start_timeout = 60 * 15

        #self.log.info("ENV: %s" % os.environ )
        # The spawned containers need to be able to talk to the hub through
        #  the proxy!
        spawner.hub_connect_port = int(os.environ['HUB_SERVICE_PORT'])
        spawner.hub_connect_ip = os.environ['HUB_SERVICE_HOST']
        #spawner.environment['JUPYTERHUB_API_URL'] = 'bollocks' #"http://%s:%s/hub/api" % (os.getenv('HUB_SERVICE_HOST'), os.getenv('HUB_SERVICE_PORT_API') )

        # Set up memory and CPU upper/lower bounds
        spawner.mem_limit = os.getenv('LAB_MEM_LIMIT') or '2G'
        spawner.cpu_limit = float(os.getenv('LAB_CPU_LIMIT')) if os.getenv('LAB_CPU_LIMIT') else 1.0
        spawner.mem_guarantee = os.getenv('LAB_MEM_GUARANTEE') or '64K'
        spawner.cpu_guarantee = float(os.getenv('LAB_CPU_GUARANTEE')) if os.getenv('LAB_CPU_GUARANTEE') else 0.02

        # Persistent shared user volume
        #volname = "jld-fileserver-home"
        #homefound = False
        #for v in spawner.volumes:
        #    self.log.info("spawner volume: %s" % (v,))
        #    if v["name"] == volname:
        #        homefound = True
        #        break
        #if not homefound:
        #    self.log.info("spawner volume %s not found" % (volname,))
        #    spawner.volumes.extend([
        #        {"name": volname,
        #         "persistentVolumeClaim":
        #         {"claimName": volname}}])
        #    spawner.volume_mounts.extend([
        #        {"mountPath": "/home",
        #         "name": volname}])

        # We are running the Lab at the far end, not the old Notebook
        spawner.default_url = '/lab'
        spawner.singleuser_image_pull_policy = 'Always'
        
        # self.log.info("HERE _state: %s" % self._state)

        #spawner.singleuser_uid = self._state["uidNumber"]
        spawner.environment['EXTERNAL_UID'] = str( self._state["uidNumber"] )
        #spawner.singleuser_fs_gid = self._state["gidNumber"]

        tuples = [ '%s:%s' % (self._state['gidCN'],self._state['gidNumber']) ]
        for i,n in enumerate(self._state["gidNumbers"]):
            tuples.append( '%s:%s' % (self._state['gidCNs'][i],n) )
        spawner.environment['EXTERNAL_GROUPS'] = ','.join( tuples )
        spawner.user_gids = tuples 

        self.log.info("Spawned environment: %s", json.dumps(
             spawner.environment, sort_keys=True, indent=4))

        #self.log.info(" new cns: %s" % (self._state["gidCNs"],))
        #default_group = 'lsst' if 'gidCNs' in self._state and 'lsst' in ':'.join(self._state["gidCNs"]) else 'ocio'
        #spawner.singleuser_node_selector = { 'group': default_group }
        #self.log.info("spawn options: %s" % (spawner,))


    @gen.coroutine
    def authenticate(self, handler, data):

        self._state = {}
        
        username = data['username']
        password = data['password']
        # Get LDAP Connection
        def getConnection(userdn, username, password):
            server = ldap3.Server(
                self.server_address,
                port=self.server_port,
                use_ssl=self.use_ssl
            )
            self.log.debug('Attempting to bind {username} with {userdn}'.format(
                    username=username,
                    userdn=userdn
            ))
            conn = ldap3.Connection(
                server,
                user=self.escape_userdn_if_needed(userdn),
                password=password,
                auto_bind=ldap3.AUTO_BIND_TLS_BEFORE_BIND,
            )
            return conn
        
        # Protect against invalid usernames as well as LDAP injection attacks
        if not re.match(self.valid_username_regex, username):
            self.log.warn('username:%s Illegal characters in username, must match regex %s', username, self.valid_username_regex)
            return None

        # No empty passwords!
        if password is None or password.strip() == '':
            self.log.warn('username:%s Login denied for blank password', username)
            return None

        isBound = False
        self.log.debug("TYPE= '%s'",isinstance(self.bind_dn_template, list))

        resolved_username = self.resolve_username(username)
        if resolved_username is None:
            return None

        bind_dn_template = self.bind_dn_template
        if isinstance(bind_dn_template, str):
            # bind_dn_template should be of type List[str]
            bind_dn_template = [bind_dn_template]

        for dn in self.bind_dn_template:
            userdn = dn.format(username=resolved_username)
            msg = 'Status of user bind {username} with {userdn} : {isBound}'
            try:
                conn = getConnection(userdn, username, password)
            except ldap3.core.exceptions.LDAPBindError as exc:
                isBound = False
                msg += '\n{exc_type}: {exc_msg}'.format(
                    exc_type=exc.__class__.__name__,
                    exc_msg=exc.args[0] if exc.args else ''
                ) 
            else:
                isBound = conn.bind()
            msg = msg.format(
                username=username,
                userdn=userdn,
                isBound=isBound
            )
            self.log.debug(msg)                
            if isBound:
                break

        if isBound:
          
            # find primary record
            self.log.warn('Looking for user in base {user_search_base}: {userattr}={username}'.format(user_search_base=self.user_search_base,userattr=self.user_attribute,username=username))
            conn.search(
                    search_base=self.user_search_base,
                    search_scope=ldap3.SUBTREE,
                    search_filter=self.search_filter.format(userattr=self.user_attribute,username=username),
                    attributes=self.attributes
            )
            if len(conn.response) == 0:
                self.log.warn('User with {userattr}={username} not found in directory'.format(
                    userattr=self.user_attribute, username=username))
                return None
            elif len(conn.response) > 1:
                self.log.warn('User with {userattr}={username} found more than {len}-fold in directory'.format(
                    userattr=self.user_attribute, username=username, len=len(conn.response)))
                return None

            #self.log.error('FOUND elif: %s' % (conn.response[0],))
            for k,v in conn.response[0]['attributes'].items():
              self._state[k] = v

            # get the gid name
            conn.search(
                    search_base=self.group_search_base,
                    search_scope=ldap3.SUBTREE,
                    search_filter="(&(objectclass=posixGroup)(gidNumber={gidNumber}))".format(gidNumber=self._state['gidNumber']),
                    attributes=self.attributes
            )
            if len(conn.response) == 0:
                self.log.warn("Could not find user's CN for gidNumber %s" % (self._state['gidNumber'],))
                return None
            elif len(conn.response) > 1:
                self.log.warn("Too many matches for user's gidNumber %s" % (self._state['gidNumber'],))
                return None

            self._state['gidCN'] = conn.response[0]['attributes']['cn'][0]

            # find other group memberships
            self.log.warn('Looking for groups in base {group_search_base}: {username}'.format(
              group_search_base=self.user_search_base,
              username=username) )
            conn.search(
                    search_base=self.group_search_base,
                    search_scope=ldap3.SUBTREE,
                    search_filter=self.group_search_filter.format(username=username),
                    attributes=self.attributes
            )
            if len(conn.response) == 0:
                self.log.warn('User {username} not found in any groups'.format(
                    username=username))
                return None
            elif len(conn.response) > 0:
                self._state['gidNumbers'] = []
                self._state['gidCNs'] = []
                # self.log.error('groups found: %s' % (conn.response,))
                for item in conn.response:
                  #self.log.info("    %s: %s" % (item['attributes']['gidNumber'],item['attributes']['cn']))
                  self._state['gidNumbers'].append( item['attributes']['gidNumber'] )
                  self._state['gidCNs'].append( item['attributes']['cn'][0] )

            return username
            
        else:
            self.log.warn('Invalid password for user {username}'.format(
                username=username,
            ))
            return None



c.JupyterHub.authenticator_class = SLACAuth
c.LDAPAuthenticator.server_address = 'ldap01.slac.stanford.edu'
c.LDAPAuthenticator.use_ssl = True
c.LDAPAuthenticator.bind_dn_template = [
  'uid={username},ou=Accounts,dc=slac,dc=stanford,dc=edu',
]
c.LDAPAuthenticator.user_attribute = 'uid'
c.LDAPAuthenticator.attributes = ['uidNumber','gidNumber','cn','mail']
c.LDAPAuthenticator.search_filter = "(&({userattr}={username}))"
c.LDAPAuthenticator.user_search_base = 'ou=Accounts,dc=slac,dc=stanford,dc=edu'

c.LDAPAuthenticator.group_search_base = 'ou=Group,dc=slac,dc=stanford,dc=edu'
c.LDAPAuthenticator.group_search_filter = "(&(objectclass=posixGroup)(memberUid={username}))"
