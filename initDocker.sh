#!/bin/bash
LOCAL_IP=`ifconfig eth0 | grep 'inet addr' | cut -d: -f2 | awk '{print $1}'`
kubectl drain $LOCAL_IP --delete-local-data
docker stop $(docker ps -a -q)
docker rm $(docker ps -a -q)
docker rmi $(docker images -q)
#init docker worker host
#install aufs soft
echo "start install aufs-tools"
apt-get install aufs-tools
#init /dev/vdb
echo "start init /dev/vdb......"
sleep 3s
mkfs -t ext4 /dev/vdb
echo "start excute mount operition......"
echo "/dev/vdb             /opt                 ext4       noatime,acl,user_xattr 1 1" >> /etc/fstab
mount -a
sleep 3s
echo "start change docker config....."
echo 'GRAPH="--graph=/opt/docker"' >> /etc/docker/dockerd
sed -i 's/${REGISTRY_MIRROR}/& ${GRAPH}/'  /usr/lib/systemd/system/dockerd.service
echo "restart dockerd........"
systemctl daemon-reload
systemctl restart dockerd
systemctl restart kubelet
kubectl uncordon $LOCAL_IP
