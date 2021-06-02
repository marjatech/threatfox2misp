import json
from pymisp import ExpandedPyMISP, MISPEvent
from pymisp.api import requests
from datetime import datetime
from config import misp_url, misp_key, misp_verifycert
from config import fetch_url, lookback_days
from config import event_info_template, info_dateformat, autopublish, tagging, type_mapping, confidence_tagging, event_distribution, event_threat_level


#####################################################
#          Functions
#####################################################

def confidence_level_to_tag(level: int) -> str:
    """
        map a confidence Level 0-100 to misp:confidence Taxonomy
    """
    confidence_tag = ''
    for tag_minvalue, tag in confidence_tagging.items():
        if level >= tag_minvalue:
            confidence_tag = tag
    return {'name': confidence_tag}


#####################################################
#          Classes
#####################################################

class ThreatFoxMISP(ExpandedPyMISP):

    def get_malpedia_tagging(self) -> list:
        """
            fetch malpedia Galaxy Clusters
        """
        galaxy = self.get_galaxy('1d1c9af9-37fa-4deb-a928-f9b0abc7354a')  # Malpedia Galaxy
        return galaxy['GalaxyCluster']

    def fetch_last_tf(self, time: int) -> list:
        """
            fetch known attributes from this source inside the defined timerange.
        """
        selector = {
            "to_ids": "0||1",
            "timestamp": f'{time}d',
            "published": "0||1",
        }
        # fetch last_known
        selector['tags'] = ['source:threatfox.abuse.ch']
        last_known = self.direct_call(f"attributes/restSearch/text", selector)
        # prepare result
        ret = last_known.split('\n')
        return ret

    def submit_tf_update(misp: ExpandedPyMISP, attributes: list) -> MISPEvent:
        """
            create/update abuse.ch MISP-Event and append the new attributes
        """
        eventinfo = event_info_template.format(datetime.now().strftime(info_dateformat))
        # logging.debug(eventinfo)
        events = misp.search(controller='events', eventinfo=eventinfo, org=1, pythonify=True)
        if events:  # current event exists already
            event = events[0]
        else:  # create a new event
            event = MISPEvent()
            event.distribution = event_distribution
            event.threat_level_id = event_threat_level
            event.analysis = 2
            event.info = eventinfo
            for tag in tagging:
                event.add_tag(tag)
            event = misp.add_event(event, pythonify=True)
        for att in attributes:
            event.add_attribute(**att)
        event.published = autopublish
        return misp.update_event(event)


class ThreatFoxHandler():
    tf_data = []

    def fetch_threatfox(self, time: int) -> dict:
        """
            Query current IOC set from ThreatFox API
        """
        post_data = f'{{ "query": "get_iocs", "days": {time} }}'
        data = requests.post(fetch_url, post_data).content.decode('utf-8')
        self.tf_data = json.loads(data)['data']
        return self.tf_data

    def convert_to_attributes(self, clusters: list) -> list:
        """
            convert IOCs to MISP-Attributes and add Galaxy-Clusters by Malware-Name
        """
        attributes = []
        att = {}
        for ioc in self.tf_data:
            att['value'] = ioc['ioc']
            att['type'] = type_mapping[ioc['ioc_type']]
            if '|' in att['type']:
                att['value'] = att['value'].replace(':', '|')
            att['Tag'] = []
            if ioc['tags']:
                # tags = [{'name': tag.strip()} for tag in ioc['tags'].split(',')]
                tags = ioc['tags']
                att['Tag'].extend(tags)
            fs = datetime.strptime(ioc['first_seen'], '%Y-%m-%d %H:%M:%S UTC')
            att['first_seen'] = datetime.timestamp(fs)
            if 'last_seen' in ioc and ioc['last_seen']:
                ls = datetime.strptime(ioc['last_seen'], '%Y-%m-%d %H:%M:%S UTC')
                att['last_seen'] = max(datetime.timestamp(fs), datetime.timestamp(ls))
            names = []
            if ioc['malware_alias']:
                names = ioc['malware_alias'].lower().split(',')
            names.append(ioc['malware_printable'].lower())
            for c in clusters:
                if c['value'].lower() in names:
                    att['Tag'].append({'name': c['tag_name']})
            if not att['Tag']:
                att['Tag'].append({'name': ioc['malware_printable']})
            # append confidence-tag
            att['Tag'].append(confidence_level_to_tag(ioc['confidence_level']))
            att['comment'] = ioc['threat_type']
            if ioc['reference']:
                att['comment'] += f"\n{ioc['reference']}"
            attributes.append(att.copy())
        return attributes


#####################################################
#          MAIN
#####################################################

if __name__ == "__main__":
    # Fetch ThreatFox
    tf = ThreatFoxHandler()
    tf.fetch_threatfox(lookback_days)
    # Get Data from MISP
    requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
    misp = ThreatFoxMISP(misp_url, misp_key, misp_verifycert)
    known = misp.fetch_last_tf(lookback_days)
    clusters = misp.get_malpedia_tagging()
    # Convert to MISP Attributes
    attributes = tf.convert_to_attributes(clusters)
    # Don't update known ones
    atts = [att for att in attributes if att['value'] not in known]
    # Finally send the update
    if atts:
        event = misp.submit_tf_update(atts)
