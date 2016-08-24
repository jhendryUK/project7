#!/usr/bin/env bash

bin=${1:-../project7.py}

function run_cmd() {
    cmd="$bin $1"
    out=$2

    rc=`$cmd`

    if [ "x$rc" != "x$out" ]; then
        echo "Unexpected output when running $cmd" >&2
        echo -e "\t We expected:    '$out'" >&2
        echo -e "\t We got:         '$rc'" >&2
        exit 1
    fi
}


###
### Error checking rules
###
echo Check for non-existant config file
run_cmd "--config ./blah.yaml" "Error: Config file ./blah.yaml does not exist"

echo Check running with empty file
run_cmd "--config ./test1.yaml" "Error: Self outbound policy is not defined"

echo Check running without any zones defined
run_cmd "--config ./test2.yaml" "Error: No zones defined"

echo Check with a zone without any interfaces
run_cmd "--config ./test3.yaml" "Error: No interfaces have been defined for zone External"

echo Check rule without defining RuleTemplate
run_cmd "--config ./test4.yaml" "Error: RuleTemplate ALLOW_ESTABLISHED not defined"

echo Check RuleTemplate when network-group not defined
run_cmd "--config ./test5.yaml" "Error: network-group RFC1918 not defined"

echo Check RuleTemplate when address-group not defined
run_cmd "--config ./test6.yaml" "Error: address-group TRUSTED_HOST not defined"

echo Check RuleTemplate when port-group not defined
run_cmd "--config ./test7.yaml" "Error: port-group HTTP_PORTS not defined"

#echo Check adding a rule to a zone which does not exist
#run_cmd "--config ./test8.yaml" "Error: "  # Silently dropped, needs an explicit error

###
### Check generated config
###

echo "All tests passed"
