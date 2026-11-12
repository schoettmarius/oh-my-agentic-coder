#!/usr/bin/env bash
set -euo pipefail

sudo apt-get update
sudo apt-get install -y bubblewrap zenity libnotify-bin libsecret-1-0 jq
