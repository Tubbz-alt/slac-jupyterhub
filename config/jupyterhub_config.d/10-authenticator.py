
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

        # self.log.info("ENV: %s" % os.environ )

        # First pulls can be really slow for the LSST stack containers,
        #  so let's give it a big timeout
        spawner.http_timeout = 60 * 15
        spawner.start_timeout = 60 * 15

        # Set up memory and CPU upper/lower bounds
        spawner.mem_limit = os.getenv('LAB_MEM_LIMIT') or '2G'
        spawner.cpu_limit = float(os.getenv('LAB_CPU_LIMIT')) if os.getenv('LAB_CPU_LIMIT') else 1.0
        spawner.mem_guarantee = os.getenv('LAB_MEM_GUARANTEE') or '64K'
        spawner.cpu_guarantee = float(os.getenv('LAB_CPU_GUARANTEE')) if os.getenv('LAB_CPU_GUARANTEE') else 0.02

        # We are running the Lab at the far end, not the old Notebook
        spawner.default_url = '/lab'
        spawner.image_pull_policy = 'Always'

        if 'uidNumber' in self._state:
            spawner.environment['EXTERNAL_UID'] = str( self._state["uidNumber"] )

        if 'gidCN' in self._state and 'gidNumber' in self._state:
            tuples = [ '%s:%s' % (self._state['gidCN'],self._state['gidNumber']) ]
            for i,n in enumerate(self._state["gidNumbers"]):
                tuples.append( '%s:%s' % (self._state['gidCNs'][i],n) )
            spawner.environment['EXTERNAL_GROUPS'] = ','.join( tuples )
            spawner.user_gids = tuples 

        self.log.info("Spawning for %s with environment: %s" % (str(user), json.dumps(spawner.environment, sort_keys=True, indent=4)) )


    def _authenticate(self, handler, data):
        username = data['username']
        password = data['password']

        # Protect against invalid usernames as well as LDAP injection attacks
        if not re.match(self.valid_username_regex, username):
            self.log.warn(
                'username:%s Illegal characters in username, must match regex %s',
                username, self.valid_username_regex
            )
            return None

        # No empty passwords!
        if password is None or password.strip() == '':
            self.log.warn('username:%s Login denied for blank password', username)
            return None

        if self.lookup_dn:
            username = self.resolve_username(username)
            if not username:
                return None

        if self.lookup_dn:
            if str(self.lookup_dn_user_dn_attribute).upper() == 'CN':
                # Only escape commas if the lookup attribute is CN
                username = re.subn(r"([^\\]),", r"\1\,", username)[0]

        bind_dn_template = self.bind_dn_template
        if isinstance(bind_dn_template, str):
            # bind_dn_template should be of type List[str]
            bind_dn_template = [bind_dn_template]

        is_bound = False
        for dn in bind_dn_template:
            if not dn:
                self.log.warn("Ignoring blank 'bind_dn_template' entry!")
                continue
            userdn = dn.format(username=username)
            if self.escape_userdn:
                userdn = escape_filter_chars(userdn)
            msg = 'Attempting to bind {username} with {userdn}'
            self.log.debug(msg.format(username=username, userdn=userdn))
            msg = "Status of user bind {username} with {userdn} : {is_bound}"
            try:
                conn = self.get_connection(userdn, password)
            except ldap3.core.exceptions.LDAPBindError as exc:
                is_bound = False
                msg += '\n{exc_type}: {exc_msg}'.format(
                    exc_type=exc.__class__.__name__,
                    exc_msg=exc.args[0] if exc.args else ''
                )
            else:
                is_bound = conn.bind()
            msg = msg.format(
                username=username,
                userdn=userdn,
                is_bound=is_bound
            )
            self.log.debug(msg)
            if is_bound:
                break

        if not is_bound:
            msg = "Invalid password for user '{username}'"
            self.log.warn(msg.format(username=username))
            raise ValueError( msg )

        if self.search_filter:
            search_filter = self.search_filter.format(
                userattr=self.user_attribute,
                username=username,
            )
            conn.search(
                search_base=self.user_search_base,
                search_scope=ldap3.SUBTREE,
                search_filter=search_filter,
                attributes=self.attributes
            )
            n_users = len(conn.response)
            if n_users == 0:
                msg = "User with '{userattr}={username}' not found in directory"
                self.log.warn(msg.format(
                    userattr=self.user_attribute,
                    username=username)
                )
                raise ValueError( msg )
            if n_users > 1:
                msg = (
                    "Duplicate users found! "
                    "{n_users} users found with '{userattr}={username}'"
                )
                self.log.warn(msg.format(
                    userattr=self.user_attribute,
                    username=username,
                    n_users=n_users)
                )
                raise ValueError( msg )

        if self.allowed_groups:
            self.log.debug('username:%s Using dn %s', username, userdn)
            found = False
            for group in self.allowed_groups:
                group_filter = (
                    '(|'
                    '(member={userdn})'
                    '(uniqueMember={userdn})'
                    '(memberUid={uid})'
                    ')'
                )
                group_filter = group_filter.format(
                    userdn=userdn,
                    uid=username
                )
                group_attributes = ['member', 'uniqueMember', 'memberUid']
                found = conn.search(
                    group,
                    search_scope=ldap3.BASE,
                    search_filter=group_filter,
                    attributes=group_attributes
                )
                if found:
                    break
            if not found:
                # If we reach here, then none of the groups matched
                msg = 'username:{username} User not in any of the allowed groups'
                self.log.warn(msg.format(username=username))
                raise ValueError( msg )

        return conn, is_bound, username


    @gen.coroutine
    def authenticate( self, handler, data):
        try:
            conn, is_bound, username = self._authenticate( handler, data )
        except:
            return None
            
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
        self._state['gidNumbers'] = []
        self._state['gidCNs'] = []
        if len(conn.response) > 0:
            # self.log.error('groups found: %s' % (conn.response,))
            for item in conn.response:
              #self.log.info("    %s: %s" % (item['attributes']['gidNumber'],item['attributes']['cn']))
              self._state['gidNumbers'].append( item['attributes']['gidNumber'] )
              self._state['gidCNs'].append( item['attributes']['cn'][0] )

        return str(username)


c.JupyterHub.authenticator_class = SLACAuth
c.LDAPAuthenticator.server_address = 'ldap01.slac.stanford.edu'
c.LDAPAuthenticator.use_ssl = True
c.LDAPAuthenticator.bind_dn_template = [
  'uid={username},ou=Accounts,dc=slac,dc=stanford,dc=edu',
]
c.LDAPAuthenticator.user_attribute = 'uid'
c.LDAPAuthenticator.attributes = ['uidNumber','gidNumber','cn','mail']
c.LDAPAuthenticator.lookup_dn_user_dn_attribute = 'cn'
c.LDAPAuthenticator.search_filter = "(&({userattr}={username}))"
c.LDAPAuthenticator.user_search_base = 'ou=Accounts,dc=slac,dc=stanford,dc=edu'

c.LDAPAuthenticator.group_search_base = 'ou=Group,dc=slac,dc=stanford,dc=edu'
c.LDAPAuthenticator.group_search_filter = "(&(objectclass=posixGroup)(memberUid={username}))"
