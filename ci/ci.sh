#!/usr/bin/env bash

script_dir=$(dirname `realpath $0`)
bin=${1:-$script_dir/../project7.py}

function run_cmd() {
    cmd="$bin $1"
    out=$2

    data=`$cmd`
    rc=$?

    if [ "x$data" != "x$out" ]; then
        echo "Unexpected output when running $cmd" >&2
        echo -e "\t We expected:    '$out'" >&2
        echo -e "\t We got:         '$data'" >&2
        exit 1
    fi

}


###
### Error checking rules
###
echo Check for non-existant config file
run_cmd "--config ${script_dir}/blah.yaml" "Error: Config file ${script_dir}/blah.yaml does not exist"

echo Check running with empty file
run_cmd "--config ${script_dir}/test1.yaml" "Error: Self outbound policy is not defined"

echo Check running without any zones defined
run_cmd "--config ${script_dir}/test2.yaml" "Error: No zones defined"

echo Check with a zone without any interfaces
run_cmd "--config ${script_dir}/test3.yaml" "Error: No interfaces have been defined for zone External"

echo Check rule without defining RuleTemplate
run_cmd "--config ${script_dir}/test4.yaml" "Error: RuleTemplate ALLOW_ESTABLISHED not defined"

echo Check RuleTemplate when network-group not defined
run_cmd "--config ${script_dir}/test5.yaml" "Error: network-group RFC1918 not defined"

echo Check RuleTemplate when address-group not defined
run_cmd "--config ${script_dir}/test6.yaml" "Error: address-group TRUSTED_HOST not defined"

echo Check RuleTemplate when port-group not defined
run_cmd "--config ${script_dir}/test7.yaml" "Error: port-group HTTP_PORTS not defined"

echo Check adding a rule to a zone which does not exist
run_cmd "--config ${script_dir}/test8.yaml" "Error: You are creating a rule in an undefined zone-pair fake_zone"

echo Check including a file which does not exist
run_cmd "--config ${script_dir}/test9.yaml" "Error: Config file ./fake_include.yaml does not exist"

###
### Check generated config
###

echo Check contents of a full generated config
cmd=`$bin --config ${script_dir}/simple_firewall.yaml >/dev/null 2>&1`
if [ $? != 0 ]; then
    echo "Error generating sample config: $cmd"
    exit 1
fi

sha512sum --quiet --status --check simple_firewall.vbash.sha512 --strict
if [ $? != 0 ]; then
    echo "Failed config generation test, output has changed"
    diff -u ${script_dir}/simple_firewall.vbash.good_config ${script_dir}/simple_firewall.vbash
    rm -f ${script_dir}/simple_firewall.vbash
    exit 1
fi

rm -f ${script_dir}/simple_firewall.vbash
echo "All tests passed"
