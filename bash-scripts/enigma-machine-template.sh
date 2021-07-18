#!/bin/bash
ARGUMENTS=$@
set echo off

if [[ -z "${EM_HOME}" ]]; then
  echo "Environment variable EM_HOME undefined"
  exit 1
else
  HOME=${EM_HOME}
fi

VM_OPTIONS=""
JAVA_OPTS="-Xms192m -Xmx192m"
exec java ${JAVA_OPTS} ${VM_OPTIONS} -jar ${HOME}/lib/${project.artifactId}-${project.version}.jar $ARGUMENTS
