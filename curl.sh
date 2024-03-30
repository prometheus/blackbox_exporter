#!/bin/bash
set -eu
# curl -s "http://localhost:9115/probe?target=https://104.197.78.225/ip2&module=http_1&hostname=g.uvoo.io&debug=true"
curl -s "http://localhost:9115/probe?target=https://104.197.78.225/ip2&module=http_2xx&hostname=g.uvoo.io&debug=true&fail_if_body_not_matches_regexp=fooo1,fooo1,fooo3"
