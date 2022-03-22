#!/bin/bash

./lynis_eval.py $1os/lynis/lynis.log -b $2 -l
./vuls_eval.py $1os/vuls/vuls.log -b $2 -l
./kube_eval.py $1k8s/kube-hunter/Kube-Hunter.Kube-Hunter/cluster.log -b $2 -cl -l
./kube_eval.py $1k8s/kube-hunter/Kube-Hunter.Kube-Hunter/pod.log -b $2 -l

mkdir $2
mv lynis_eval_* $2
mv vuls_eval_* $2
mv kube_eval_* $2