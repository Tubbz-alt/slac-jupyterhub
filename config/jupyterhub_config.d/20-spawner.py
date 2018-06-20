"""The spawner is the KubeSpawner, modified to use the options form data.
"""
import datetime
import escapism
import json
import kubespawner
import os
import urllib
from urllib.error import HTTPError
from kubespawner.objects import make_pod
from tornado import gen
import yaml
import glob

from traitlets import Unicode, Int, Bool, List, Union

# Spawn the pod with custom settings retrieved via token additional scope.
class SLACSpawner(kubespawner.KubeSpawner):
    """Spawner to use our custom environment settings as reflected through
    auth_state."""

    node_selectors = List(
        config=True,
        default=[],
        allow_none=False,
        help="""
        Filter map of mapping users and group to Kubernetes node selectors and required persistent volume claims.
        ```
        """
    )

    user_gids = List(
         config=True,
         default=[],
         allow_none=True,
         help="work dammit"
    )

    node_selector_config_file = Unicode('',
        help="""
        A YAML configuration file containing the mapping of gid and images specifications to image placement (node selector)
        and volume/volume_mount options for that image.
        """
    ).tag(config=True)

    images_config_d = Unicode('',
        help="""
        Directory of YAML configuration files of images to spawn
        """
    )
    
    @property
    def options_form(self):

        if not self.images_config_d:
            self.images_config_d = '/opt/jupyterhub/config/images.d/'
        self.log.info("Loading Image Selector from %s" % (self.images_config_d,))
        # open directory
        conf_files = glob.glob( self.images_config_d + '/*.yaml' )
        images = []
        # for each file read yaml
        for f in conf_files:
            self.log.info('  scanning file: %s' % (f,))
            with open(f, 'r') as conf:
                try:
                    images.append( yaml.load(conf) )
                except Exception:
                    self.log.warn("Could not parse image list %s" % f)
           
        optform = ''
        for section in images:
            if 'title' in section:
                optform += '<h3>%s</h3><br/>\n' % section['title']
            if 'updated' in section:
                optform += "updated at %s<br>\n" % section['updated']
            if 'images' in section:
                for image in section['images']:
                    optform += '<input type="radio" name="kernel_image" value="%s">%s<br>\n' % (image['image'], image['description'])

        return optform

    @gen.coroutine
    def get_pod_manifest(self):
        """
        Make a pod manifest that will spawn current user's notebook pod.
        """
        if callable(self.singleuser_uid):
            singleuser_uid = yield gen.maybe_future(self.singleuser_uid(self))
        else:
            singleuser_uid = self.singleuser_uid

        if callable(self.singleuser_fs_gid):
            singleuser_fs_gid = yield \
                gen.maybe_future(self.singleuser_fs_gid(self))
        else:
            singleuser_fs_gid = self.singleuser_fs_gid

        if self.cmd:
            real_cmd = self.cmd + self.get_args()
        else:
            real_cmd = None

        # Default set of labels, picked up from
        # https://github.com/kubernetes/helm/blob/master/docs/chart_best_practices/labels.md
        labels = {
            'heritage': 'jupyterhub',
            'component': 'singleuser-server',
            'app': 'jupyterhub',
            'hub.jupyter.org/username': escapism.escape(self.user.name)
        }

        labels.update(self._expand_all(self.singleuser_extra_labels))

        pod_name = self.pod_name
        image_spec = (self.singleuser_image_spec or os.getenv("LAB_IMAGE")
                      or "lsstsqre/jld-lab:latest")
        image_name = image_spec
        if self.user_options:
            if self.user_options.get('kernel_image'):
                image_spec = self.user_options.get('kernel_image')
                image_name = image_spec
                self.log.info("Replacing image spec from options form: %s" %
                              image_spec)
        self.singleuser_image_spec = image_spec
        s_idx = image_spec.find('/')
        c_idx = image_spec.find(':')
        tag = "latest"
        if s_idx != -1:
            image_name = image_spec[(s_idx + 1):]
            if c_idx > 0:
                image_name = image_spec[(s_idx + 1):c_idx]
                tag = image_spec[(c_idx + 1):]
        pn_template = image_name + "-{username}-" + tag
        self.log.info('running image: %s' % (image_name,))

        auth_state = yield self.user.get_auth_state()
        self.log.info("AuthState: %s"%(auth_state,))
        if auth_state and "id" in auth_state:
            if auth_state["id"] != self.user.id:
                self.log.info("Updating userid from %d to %d" %
                              (self.user.id, auth_state["id"]))

        pod_name = self._expand_user_properties(pn_template)
        self.pod_name = pod_name
        self.log.info("Replacing pod name from options form: %s" % pod_name)

        # ast chance to overload some env variables for the notebox
        pod_env = self.get_env()

        idle_timeout = int(os.getenv('LAB_IDLE_TIMEOUT') or 43200)
        if idle_timeout > 0 and 'JUPYTERLAB_IDLE_TIMEOUT' not in pod_env:
            pod_env['JUPYTERLAB_IDLE_TIMEOUT'] = str(idle_timeout)

        oauth_callback = os.getenv('OAUTH_CALLBACK_URL')
        endstr = "/hub/oauth_callback"
        if oauth_callback and oauth_callback.endswith(endstr):
            pod_env['EXTERNAL_URL'] = oauth_callback[:-len(endstr)]

        # use the hub service instead of pod
        if os.getenv('HUB_SERVICE_HOST') and os.getenv('HUB_SERVICE_PORT_API'):
            pod_env['JUPYTERHUB_API_URL'] = "http://%s:%s/hub/api" % (os.getenv('HUB_SERVICE_HOST'), os.getenv('HUB_SERVICE_PORT_API') )

        # determine which labels to schedule the jupyterlab pod on
        # get names of groups
        #self.log.info("SPAWN ENV: %s" % (self.environment,))
        #self.log.info("PASS: %s" % (self.user_gids,))
        gnames = [ i.split(':')[0] for i in self.user_gids ]
        
        spawn_on = {}
        volumes = []
        volume_mounts = []
        config = {}
        spec = {}
        with open( self.node_selector_config_file, 'r' ) as f:
            config = yaml.safe_load(f)
            if 'node_defaults' in config:
                this = config['node_defaults']
                if 'spawn_on' in this:
                    spawn_on = this['spawn_on']
                if 'spec' in this:
                    spec = this['spec']
                    
        self.log.info("node-selectors config: %s" % (config,))
        
        if 'node_selectors' in config:
            for idx, item in enumerate(config['node_selectors']):
                if 'filter' in item:
                    this = item['filter']
                    matching = []

                    self.log.info("checking filter: %s" % (this,))
                    for n in ( 'gnames', 'images', 'uid'):
                        if n in this:
                            a = []
                            if n == 'gnames':
                                a = gnames
                            elif n == 'images':
                                a = [ image_name, ]
                            # TODO: hwo to get the uid?
                            self.log.info("  %s against %s" % (n, a))
                            if set( this[n] ).intersection( a ):
                                matching.append( True )
                            else:
                                matching.append( False )
                    self.log.info(" matching: %s" % (matching,))
                    if False in matching:
                        continue
                    else:
                        spawn_on = item['spawn_on']
                        spec = item['spec']
                        if 'cpu' in spec:
                            self.cpu_limit = spec['cpu']
                            #self.cpu_guarantee = spec['cpu']
                        if 'memory' in spec:
                            self.mem_limit = spec['memory']
                            #self.mem_guarantee = spec['memory']
                        self.log.info(" using spec: %s" % (spec,))
                        break

        self.log.info("spawning pod with NodeSelector: %s, spec %s" % (spawn_on,spec))
        return make_pod(
            name=self.pod_name,
            image_spec=self.singleuser_image_spec,
            image_pull_policy=self.singleuser_image_pull_policy,
            image_pull_secret=self.singleuser_image_pull_secrets,
            port=self.port,
            cmd=real_cmd,
            node_selector=spawn_on,
            run_as_uid=singleuser_uid,
            fs_gid=singleuser_fs_gid,
            run_privileged=self.singleuser_privileged,
            env=pod_env,
            volumes=self._expand_all(spec['volumes']) if 'volumes' in spec else self._expand_all([]),
            volume_mounts=self._expand_all(spec['volume_mounts']) if 'volume_mounts' in spec else self._expand_all([]),
            working_dir=self.singleuser_working_dir,
            labels=labels,
            cpu_limit=self.cpu_limit,
            cpu_guarantee=self.cpu_guarantee,
            mem_limit=self.mem_limit,
            mem_guarantee=self.mem_guarantee,
            extra_resource_limits=spec['extra_resource_limits'] if 'extra_resource_limits' in spec else {},
            lifecycle_hooks=self.singleuser_lifecycle_hooks,
            init_containers=self.singleuser_init_containers,
            service_account=None
        )

    def options_from_form(self, formdata=None):
        options = {}
        if (formdata and 'kernel_image' in formdata and
                formdata['kernel_image']):
            options['kernel_image'] = formdata['kernel_image'][0]
        return options



c.JupyterHub.spawner_class = SLACSpawner
c.SLACSpawner.node_selector_config_file = '/opt/jupyterhub/config/node-selectors.yaml'
c.SLACSpawner.images_config_d = '/opt/jupyterhub/config/images.d/'

c.SLACSpawner.start_timeout = 60
c.SLACSpawner.http_timeout = 60


