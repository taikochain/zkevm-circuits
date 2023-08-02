#!/bin/bash
set -e
#set -x
sudo pkill sadc
echo "Restarting sysstat"
sudo systemctl stop sysstat.service
sudo rm -rf /var/log/sysstat/*

sleep 10

sudo systemctl start sysstat.service

sleep 5

nohup sudo /usr/lib/sysstat/sadc 10 604800 /var/log/sysstat/ >/dev/null 2>&1 &
disown
echo "Sysstat restarted"
