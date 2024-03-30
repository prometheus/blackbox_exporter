#!/bin/bash
set -eu

blackbox_exporter --config.file="blackbox.yml"
