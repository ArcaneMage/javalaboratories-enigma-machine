#!/bin/bash
set echo off

if [[ -z "${EM_HOME}"]]; then
  echo "Environment variable EM_HOME undefined"
  exit 1
else
  HOME=${EM_HOME}
fi

VM_OPTIONS=""
JAVA_OPTS="-Xms192m -Xmx192m"
java ${JAVA_OPTS} -jar ${VM_OPTIONS} ${HOME}/lib/${project.artifactId}-${project.version}.jar "$@"
