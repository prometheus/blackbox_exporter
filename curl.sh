#!/bin/bash
set -eu
# curl -s "http://localhost:9115/probe?target=https://104.197.78.225/ip2&module=http_1&hostname=g.uvoo.io&debug=true"

# curl -s "http://localhost:9115/probe?target=https://104.197.78.225/ip&module=http_custom&hostname=g.uvoo.io&debug=true&fail_if_body_not_matches_regexp=fooo1,fooo1,fooo3"

# curl -s "http://localhost:9115/probe?target=https://104.197.78.225/ip&module=http_2xx&hostname=g.uvoo.io&debug=true&fail_if_body_not_matches_regexp=104"
# curl -s "http://localhost:9115/probe?target=https://g.uvoo.io/ip&module=http_2xx&debug=true&fail_if_body_not_matches_regexp=104"
# curl -s "http://localhost:9115/probe?target=https://uvoo.me&module=http_2xx&debug=true&fail_if_body_not_matches_regexp=uvoofff,asdf"
curl -s "http://localhost:9115/probe?target=https://uvoo.me&module=http_2xx&debug=true&body_matches=uvoo,wp-content"
