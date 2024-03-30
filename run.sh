#!/bin/bash
set -eu

# blackbox_exporter --config.file="blackbox.yml"
# ./blackbox_exporter_j --config.file="blackbox.yml"
./blackbox_exporter --config.file="blackbox.yml"
