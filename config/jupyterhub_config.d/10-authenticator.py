
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
        spawner.http_timeout = 60 * 10 
        spawner.start_timeout = 60 * 10

        # Set up memory and CPU upper/lower bounds
        spawner.mem_limit = os.getenv('LAB_MEM_LIMIT') or '2G'
        spawner.cpu_limit = float(os.getenv('LAB_CPU_LIMIT')) if os.getenv('LAB_CPU_LIMIT') else 1.0
        spawner.mem_guarantee = os.getenv('LAB_MEM_GUARANTEE') or '64K'
        spawner.cpu_guarantee = float(os.getenv('LAB_CPU_GUARANTEE')) if os.getenv('LAB_CPU_GUARANTEE') else 0.02

        # We are running the Lab at the far end, not the old Notebook
        spawner.default_url = '/lab'
        spawner.image_pull_policy = 'Always'

        # set uid and gid permissions
        u = str(user).split()[0].replace('<User(','') # wow... hack or what?
        ext_uid, ext_groups = self._getUserGroup( u )
        spawner.environment['EXTERNAL_UID'] = str(ext_uid)
        spawner.environment['EXTERNAL_GROUPS'] = ','.join( ext_groups )
        spawner.user_gids = ext_groups

        self.log.info("Spawning for %s with environment: %s" % (str(user), json.dumps(spawner.environment)) ) 


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

    def _getUserGroup( self, username ):
            
        self.log.debug('Looking for user in base {user_search_base}: {userattr}={username}'.format(user_search_base=self.user_search_base,userattr=self.user_attribute,username=username))
        data = {}
        _conn = None
        retry = 3
        while retry > 0:
            try:
                self.log.info("searching ldap...")
                # _conn = self._state['conn']
                server = ldap3.Server( self.server_address, port=self.server_port, use_ssl=self.use_ssl )
                _conn = ldap3.Connection( server )
                _conn.bind()
                _conn.search(
                    search_base=self.user_search_base,
                    search_scope=ldap3.SUBTREE,
                    search_filter=self.search_filter.format(userattr=self.user_attribute,username=username),
                    attributes=self.attributes
                )
                retry = 0
            except Exception as e:
                self.log.warn("Error connecting to ldap: %s" % (e,))
                retry = retry - 1
                if retry == 0:
                    raise Exception('Please log-out and log-back in to proceed.')

        if len(_conn.response) == 0:
            raise Exception('User with {userattr}={username} not found in directory'.format(
                userattr=self.user_attribute, username=username))
        elif len(_conn.response) > 1:
            raise Exception('User with {userattr}={username} found more than {len}-fold in directory'.format(
                userattr=self.user_attribute, username=username, len=len(_conn.response)))
        for k,v in _conn.response[0]['attributes'].items():
             data[k] = v

        # get the gid name
        _conn.search(
                search_base=self.group_search_base,
                search_scope=ldap3.SUBTREE,
                search_filter="(&(objectclass=posixGroup)(gidNumber={gidNumber}))".format(gidNumber=data['gidNumber']),
                attributes=self.attributes
        )
        if len(_conn.response) == 0:
            raise Exception( "Could not find user's CN for gidNumber %s" % (data['gidNumber'],) )
        elif len(_conn.response) > 1:
            raise Exception("Too many matches for user's gidNumber %s" % (data['gidNumber'],) )
            
        data['gidCN'] = _conn.response[0]['attributes']['cn'][0]

        # find other group memberships
        self.log.debug('Looking for groups in base {group_search_base}: {username}'.format(
          group_search_base=self.user_search_base,
          username=username) )
        _conn.search(
                search_base=self.group_search_base,
                search_scope=ldap3.SUBTREE,
                search_filter=self.group_search_filter.format(username=username),
                attributes=self.attributes
        )
        
        data['gidNumbers'] = []
        data['gidCNs'] = []
        if len(_conn.response) > 0:
            # self.log.error('groups found: %s' % (_conn.response,))
            for item in _conn.response:
              #self.log.info("    %s: %s" % (item['attributes']['gidNumber'],item['attributes']['cn']))
              data['gidNumbers'].append( item['attributes']['gidNumber'] )
              data['gidCNs'].append( item['attributes']['cn'][0] )

        tuples = [ '%s:%s' % (data['gidCN'], data['gidNumber']) ]
        for i,n in enumerate(data["gidNumbers"]):
            tuples.append( '%s:%s' % (data['gidCNs'][i],n) )
        
        return data['uidNumber'], tuples
        

    @gen.coroutine
    def authenticate( self, handler, data):
        try:
            self.log.info("authenticate()")
            self._state['conn'], is_bound, username = self._authenticate( handler, data )
        except:
            return None
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
