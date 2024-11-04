#!/usr/bin/bash


Help()
{
   # Display Help
   echo "Usage: ./collect.sh [OPTION]... <product_name>"
   echo "Collect K8S clusters configuration"
   echo "Date and time is added to the filename with this format %j%m%Y_%H%M%S"
   echo
   echo "Mandatory arguments to long options are mandatory for short options too."
   echo
   echo "  -h, --help               display help and exit"
   echo "  -p, --product-name       add a product name to specify in the zip file"
   echo
   echo "Examples:"
   echo "  ./collect.sh -p occne   Standard input is copied in the filename then collecting."
   echo "  ./collect.sh          Just collecting."
   echo
}

function args()
{
# read arguments
  options=$(getopt -o hp: --long help,product-name: -- "$@")

  [ $? -eq 0 ] || {
      echo "Try './collect.sh --help' for more information."
      exit 1
  }

  eval set -- "$options"

  while true; do
      case "$1" in
      -h|--help)
          Help
          exit;;
      -p|--product-name)
          shift; # The arg is next in position args
          PRODUCT_NAME=$1
          ;;
      *)
          break
          ;;
      esac
  done
}

args $0 "$@"

DATE=$(date "+%d%m%Y_%H%M%S")
HOSTNAME=$(cat /etc/hostname)

if [[ -z "$PRODUCT_NAME" ]]
then
  COLLECT_PATH="collect-$HOSTNAME-$DATE"
else
  COLLECT_PATH="collect-$PRODUCT_NAME-$HOSTNAME-$DATE"
fi

mkdir -p $COLLECT_PATH
kubectl get nodes -o json > $COLLECT_PATH/nodes.json
kubectl get pods -A -o json > $COLLECT_PATH/pods.json
kubectl get clusterroles -A -o json > $COLLECT_PATH/clusterroles.json
kubectl get roles -A -o json > $COLLECT_PATH/roles.json
kubectl get clusterrolebindings -A -o json > $COLLECT_PATH/clusterrolebindings.json
kubectl get rolebindings -A -o json > $COLLECT_PATH/rolebindings.json
kubectl get secrets -A -o json > $COLLECT_PATH/secrets.json
kubectl get svc -A -o json > $COLLECT_PATH/services.json

zip -r $COLLECT_PATH.zip $COLLECT_PATH
rm -rf $COLLECT_PATH
