#!/bin/env python

import json
import datetime
import urllib
import urllib.parse
import urllib.request
from urllib.error import HTTPError

import yaml
from pprint import pformat


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



if __name__ == '__main__':
    
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

    d = {
        'title': "LSST lsstsqre/jld-lab Images",
        'updated': nowstr,
        'images': []
    }
    
    for idx, img in enumerate(lnames):
        
        # print( "%s - %s" % (img, ldescs[idx]) )
        d['images'].append({
            'description': ldescs[idx],
            'image': img
        })

    # print( pformat( d ) )
    print( yaml.dump( d ) )