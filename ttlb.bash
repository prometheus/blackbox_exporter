#!/bin/bash

# start port forwarding

REGIONS=("pulsar-us-east-1" "pulsar-us-east-2" "pulsar-us-west-2" "pulsar-eu-central-1" "pulsar-ap-southeast-1")
MODULES=("iperf_xs" "iperf_s" "iperf_m" "iperf_l" "iperf_xl" "iperf_xxl")

while :
do
  for REGION in "${REGIONS[@]}"
  do
    for MODULE in "${MODULES[@]}"
    do
      echo "restarting iperf deployment in $REGION"
      kubectl rollout restart deployment iperf --namespace pulsar --context $REGION
      sleep 10
      POD_NAME=$(kubectl --context $REGION --namespace pulsar get pods | grep iperf | grep Running | awk '{print $1}')
      echo "forwarding iperf port from $POD_NAME"
      kubectl --context $REGION --namespace pulsar port-forward "$POD_NAME" 5201:5201 &
      PORTFORWARD_PID=$!

      PUSH_NAME=$(kubectl --context pulsar-us-east-1 --namespace monitoring get pods | grep pushgateway | grep Running | awk '{print $1}')
      echo "forwarding pushgateway port from $PUSH_NAME"
      kubectl port-forward "$PUSH_NAME" --namespace monitoring --context pulsar-us-east-1 9091:9091 &
      PUSHFORWARD_PID=$!

      sleep 10
      echo "curling http://localhost:9115/probe?target=$REGION&module=$MODULE"
      curl -s -o /dev/null "http://localhost:9115/probe?target=$REGION&module=$MODULE" # /etc/hosts has the regions above aliased to 127.0.0.1 to ensure the labels work
      sleep 20
      echo "ending port forwarding"
      kill $PORTFORWARD_PID
      kill $PUSHFORWARD_PID
    done

  done
done

