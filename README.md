# ThreatFox2Misp

Creating a Feed of MISP Events from ThreatFox (by abuse.ch)

## What will it do?

This will fetch IOCs from ThreatFox by Abuse.ch, convert them to feature-rich MISP-Attributes and sumbit them into a Feed of Events on a MISP instance.
It can be scheduled and will always keep updating the Event with new IOCs, or create a new one if there is none for this day yet.
The generated Events include:
- Malpedia-Galaxy Clusters
- MISP-Taxonomy tags for Confidence-Level
- Tags as submitted on ThreatFox
- threat_type and reference-link as Comment

![image](https://user-images.githubusercontent.com/72734273/110951850-d08fd000-8345-11eb-82a9-6954c27ec7e1.png)


## Deployment

To get this running there's just a few simple things to do. 
- First make sure to setup a venv, then:
```
git clone https://github.com/marjatech/threatfox2misp
cd threatfox2misp
cp config.example.py config.py
```
- Check your [Configuration](#configuration)

- You can run it manually or schedule it in your preferred way now:
```
venv/bin/python3 threatfox2misp.py
```

## Configuration

Configuration is done inside [config.py](config.py)
Defaults are fine first, only `misp_url` and `misp_key` have to be set. 

## Built With

* [PyMISP](https://github.com/MISP/PyMISP) - Python Framework for MISP
* [ThreatFox](https://threatfox.abuse.ch/api/) - ThreatFox Project by Abuse.ch

## License

This project is licensed under GPLv3 - see the [LICENSE](LICENSE) file for details

