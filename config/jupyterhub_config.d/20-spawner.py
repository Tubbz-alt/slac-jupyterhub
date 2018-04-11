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

    
    def _options_form_default(self):
        optform = ""

        optform += '<h3>SLAC JupyterLab Images</h3><br/>\n'
        optform += '<input type="radio" name="kernel_image" value="%s">%s<br>\n' % ('slaclab/slac-jupyterlab', 'SLAC JupyterLab Image')
        # optform += '<input type="radio" name="kernel_image" value="%s">%s<br>\n' % ('new_image_2', 'new_image_2_description')

        # Make options form by scanning container repository
        try:
            scanner = ScanRepo(host="hub.docker.com",
                           owner="lsstsqre",
                           name="jld-lab",
                           json=True,
                           )
            scanner.scan()
            lnames, ldescs = scanner.extract_image_info()
            if not lnames or len(lnames) < 2:
                raise Exception("could not scan images at lsstsqre/jld-lab")

            now = datetime.datetime.utcnow()
            nowstr = now.ctime()
            if not now.tzinfo:
                nowstr += " UTC"

            title = "LSST lsstsqre/jld-lab Images" 
            optform += "<h3>LSST lsstsqre/jld-lab Images</h3><br/>\n"
            optform += "updated at %s<br>\n" % nowstr
            for idx, img in enumerate(lnames):
                optform += "      "
                optform += '<input type="radio" name="kernel_image" value="%s">%s<br>\n' % (img, ldescs[idx])

        except (ValueError, HTTPError) as e:
            self.log.warning("Could scan images from from %s: %s/%s [%s]" %
                             (host, owner, repo, str(e)))

        return optform

    @property
    def options_form(self):
        return self._options_form_default()

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
        self.log.info('image: %s' % (image_name,))

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
        node_selectors = {}
        with open( self.node_selector_config_file, 'r' ) as config:
            node_selectors = yaml.safe_load(config)
            if 'node_defaults' in node_selectors:
                this = node_selectors['node_defaults']
                if 'spawn_on' in this:
                    spawn_on = this['spawn_on']
                if 'volumes' in this:
                    volumes = this['volumes']
                if 'volume_mounts' in this:
                    volume_mounts = this['volume_mounts']

        self.log.info("NODE SELECTORS: %s" % (node_selectors,))
        self.log.info("DEFAULTS: %s / %s / %s" % (spawn_on,volumes,volume_mounts))
        
        selector_idx = None
        if 'node_selectors' in node_selectors:
            for idx, item in enumerate(node_selectors['node_selectors']):
                if 'gnames' in item:
                    if set(item['gnames']).intersection(gnames):
                        self.log.info("MATCH ON %s" % (item,))
                        # match on image name if its defined
                        if 'image' in item:
                            if item['image'] == image_name:
                                spawn_on = item['spawn_on']
                                selector_idx = idx
                        else:
                            spawn_on = item['spawn_on']
                            selector_idx = idx
                        # match first
                        break

        self.log.info("spawning pod with NodeSelector: %s, idx %s" % (spawn_on,selector_idx))
        if isinstance(selector_idx, int):
            volumes = node_selectors['node_selectors'][idx]['volumes']
            volume_mounts = node_selectors['node_selectors'][idx]['volume_mounts']

        self.log.info("  with storage spec: volumes=%s, volume_mounts=%s" % (volumes, volume_mounts) )

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
            volumes=self._expand_all(volumes),
            volume_mounts=self._expand_all(volume_mounts),
            working_dir=self.singleuser_working_dir,
            labels=labels,
            cpu_limit=self.cpu_limit,
            cpu_guarantee=self.cpu_guarantee,
            mem_limit=self.mem_limit,
            mem_guarantee=self.mem_guarantee,
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


class ScanRepo(object):
    """Class to scan repository and create results.

       Based on:
       https://github.com/shangteus/py-dockerhub/blob/master/dockerhub.py"""

    host = ''
    path = ''
    owner = ''
    name = ''
    data = {}
    debug = False
    json = False
    insecure = False
    sort_field = "comp_ts"
    dailies = 3
    weeklies = 2
    releases = 1

    def __init__(self, host='', path='', owner='', name='',
                 dailies=3, weeklies=2, releases=1,
                 json=False,
                 insecure=False, sort_field="", debug=False):
        if host:
            self.host = host
        if path:
            self.path = path
        if owner:
            self.owner = owner
        if name:
            self.name = name
        if dailies:
            self.dailies = dailies
        if weeklies:
            self.weeklies = weeklies
        if releases:
            self.releases = releases
        if json:
            self.json = json
        protocol = "https"
        if insecure:
            self.insecure = insecure
            protocol = "http"
        if sort_field:
            self.sort_field = sort_field
        if debug:
            self.debug = debug
        if not self.path:
            self.path = ("/v2/repositories/" + self.owner + "/" +
                         self.name + "/tags")
        self.url = protocol + "://" + self.host + self.path

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def close(self):
        """Close the session"""
        if self._session:
            self._session.close()

    def extract_image_info(self):
        """Build image name list and image description list"""
        cs = []
        for k in ["daily", "weekly", "release"]:
            cs.extend(self.data[k])
        ldescs = []
        for c in cs:
            tag = c["name"].split(":")[-1]
            if tag[0] == "r":
                rmaj = tag[1:3]
                rmin = tag[3:]
                ld = "Release %s.%s" % (rmaj, rmin)
            elif tag[0] == "w":
                year = tag[1:5]
                week = tag[5:]
                ld = "Weekly %s_%s" % (year, week)
            elif tag[0] == "d":
                year = tag[1:5]
                month = tag[5:7]
                day = tag[7:]
                ld = "Daily %s_%s_%s" % (year, month, day)
            ldescs.append(ld)
        ls = [self.owner + "/" + self.name + ":" + x["name"] for x in cs]
        return ls, ldescs

    def report(self):
        """Print the tag data"""
        if self.json:
            print(json.dumps(self.data, sort_keys=True, indent=4))
        else:
            ls, ldescs = self.extract_image_info()
            ldstr = ",".join(ldescs)
            lstr = ",".join(ls)
            print("# Environment variables for Jupyter Lab containers")
            print("LAB_CONTAINER_NAMES=\'%s\'" % lstr)
            print("LAB_CONTAINER_DESCS=\'%s\'" % ldstr)
            print("export LAB_CONTAINER_NAMES LAB_CONTAINER_DESCS")

    def get_data(self):
        """Return the tag data"""
        return self.data

    def _get_url(self, **kwargs):
        params = None
        resp = None
        url = self.url
        if kwargs:
            params = urllib.parse.urlencode(kwargs)
            url += "?%s" % params
        headers = {"Accept": "application/json"}
        req = urllib.request.Request(url, None, headers)
        resp = urllib.request.urlopen(req)
        page = resp.read()
        return page

    def scan(self):
        url = self.url
        results = []
        page = 1
        while True:
            try:
                resp_bytes = self._get_url(page=page)
            except Exception as e:
                raise ValueError("Failure retrieving %s: %s [ data: %s ]" %
                                 (url, str(e),
                                  str(resp_bytes.decode("utf-8"))))
            resp_text = resp_bytes.decode("utf-8")
            try:
                j = json.loads(resp_text)
            except ValueError:
                raise ValueError("Could not decode '%s' -> '%s' as JSON" %
                                 (url, str(resp_text)))
            results.extend(j["results"])
            if "next" not in j or not j["next"]:
                break
            page = page + 1
        self._reduce_results(results)

    def _reduce_results(self, results):
        sort_field = self.sort_field
        r_candidates = []
        w_candidates = []
        d_candidates = []
        for res in results:
            vname = res["name"]
            fc = vname[0]
            res["comp_ts"] = self._convert_time(res["last_updated"])
            if fc == "r":
                r_candidates.append(res)
            if fc == "w":
                w_candidates.append(res)
            if fc == "d":
                d_candidates.append(res)
        r_candidates.sort(key=lambda x: x[sort_field], reverse=True)
        w_candidates.sort(key=lambda x: x[sort_field], reverse=True)
        d_candidates.sort(key=lambda x: x[sort_field], reverse=True)
        r = {}
        r["daily"] = d_candidates[:self.dailies]
        r["weekly"] = w_candidates[:self.weeklies]
        r["release"] = r_candidates[:self.releases]
        for tp in r:
            for v in r[tp]:
                del(v["comp_ts"])
        self.data = r

    def _convert_time(self, ts):
        f = '%Y-%m-%dT%H:%M:%S.%f%Z'
        if ts[-1] == "Z":
            ts = ts[:-1] + "UTC"
        return datetime.datetime.strptime(ts, f)


c.JupyterHub.spawner_class = SLACSpawner
c.SLACSpawner.node_selector_config_file = '/opt/jupyterhub/config/node-selectors.yaml'

c.SLACSpawner.start_timeout = 60
c.SLACSpawner.http_timeout = 60



# c.SLACSpawner.singleuser_node_selector = { 'group': 'ocio' }
# c.SLACSpawner.volumes = [ {'name': 'generic-user-home', 'persistentVolumeClaim': { 'claimName': 'generic-user-home' }} ]
# c.SLACSpawner.volume_mounts = [ { 'mountPath': '/home/', 'name': 'generic-user-home' } ]
# # overrides if user is in matched group and runs image
# c.SLACSpawner.node_selectors = [
#     {
#         'gnames': ['lsst','lsst-ccs',], 'image': 'jld-lab', 'spawn_on': { 'group': 'lsst' },
#         'volumes': [ {'name': 'lsst-home', 'persistentVolumeClaim': { 'claimName': 'lsst-home' }}, {'name': 'lsst-data', 'persistentVolumeClaim': { 'claimName': 'lsst-data' }} ],
#         'volume_mounts': [ { 'mountPath': '/home/', 'name': 'lsst-home' }, { 'mountPath': '/data/', 'name': 'lsst-data' } ],
#     },
# ]

