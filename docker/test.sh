#!/bin/bash
usage="Usage: `basename $0` (build|deplay|test|withdraw|all)"
command=$1

function build() {
    if [[ "$(docker images -q natbee:0.0.1 2> /dev/null)" != "" ]]; then
        docker rmi natbee:0.0.1
    fi
    docker build -t natbee:0.0.1 -f ./docker/Dockerfile .
}

function deploy() {
    docker pull
    if [ $? -ne 0 ]; then
        echo ''
        echo 'docker pull failed'
        exit
    fi
    docker network create --subnet=192.168.10.0/24 wan1
    docker network create --subnet=192.168.20.0/24 wan2
    docker network create --subnet=192.168.30.0/24 lan1
    docker network create --subnet=192.168.40.0/24 lan2
    docker run --name=nat-client --net=wan1 --ip=192.168.10.2 -d 
    docker run --name=fnat-client --net=wan2 --ip=192.168.20.2 -d
    docker run --name=nat-rs1 --net=lan1 --ip=192.168.30.11 -d
    docker run --name=nat-rs2 --net=lan1 --ip=192.168.30.22 -d
    docker run --name=fnat-rs1 --net=lan2 --ip=192.168.20.11 -d
    docker run --name=fnat-rs2 --net=lan2 --ip=192.168.40.22 -d
    docker exec nat-client apk add curl
    docker exec fnat-client apk add curl
    sleep 5

    docker run --name=natbee --net=host --privileged=true -d natbee:0.0.1
    sleep 3

    curl http://192.168.30.11:8080 --max-time 2
    curl http://192.168.30.22:8080 --max-time 2
    curl http://192.168.40.11:8080 --max-time 2
    curl http://192.168.40.22:8080 --max-time 2
}

function test() {
    docker exec nat-client curl http://192.168.10.1:8080 --max-time 2
    if [ $? -eq 0 ]; then
        echo ''
        echo 'NAT TEST RESULT: SUCC'
        echo ''
    else
        echo ''
        echo 'NAT TEST RESULT: FAIL'
        echo ''
    fi
    docker exec fnat-client curl http://192.168.20.1:8080 --max-time 2
    if [ $? -eq 0 ]; then
        echo ''
        echo 'FNAT TEST RESULT: SUCC'
        echo ''
    else
        echo ''
        echo 'FNAT TEST RESULT: FAIL'
        echo ''
    fi
}

function withdraw() {
    docker stop natbee
    docker rm -f natbee
    docker rmi natbee:0.0.1
    docker rm -f nat-client
    docker rm -f fnat-client
    docker rm -f nat-rs1
    docker rm -f nat-rs2
    docker rm -f fnat-rs1
    docker rm -f fnat-rs2
    docker network rm wan1
    docker network rm wan2
    docker network rm lan1
    docker network rm lan2
}

case $command name
    (build)
        build
        ;;
    (deploy)
        deploy
        ;;
    (test)
        test
        ;;
    (withdraw)
        withdraw
        ;;
    (all)
        build
        deploy
        test
        withdraw
        ;;
    (*)
        echo "invalid command"
        echo "$usage"
        ;;
esac