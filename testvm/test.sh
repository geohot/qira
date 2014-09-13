#!/bin/bash -e
vagrant destroy
vagrant up
rm -rf /tmp/qira_release
mkdir -p /tmp/qira_release
scp e:~/qira/distrib/*.xz /tmp/qira_release/.
vagrant ssh-config > /tmp/qira_release/ssh_config
scp -F /tmp/qira_release/ssh_config /tmp/qira_release/*.xz default:~/
ssh -F /tmp/qira_release/ssh_config -L 3002:localhost:3002 default

